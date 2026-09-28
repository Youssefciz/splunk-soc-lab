"""
Splunk AI Triage

Pulls detection results from Splunk, pseudonymizes sensitive values, sends them to
Google Gemini for triage, correlates the findings into a single attack chain, and
writes a Markdown report for analyst review. The AI recommends; a human decides.

Developed collaboratively with Claude (Anthropic). I came up with the concept, set the
requirements, built and configured the Splunk lab, debugged and tested the script against
the BOTSv1 dataset, reviewed the AI output, and directed the v2 improvements. Claude
assisted with writing and reviewing the code. Google Gemini is the model the script
calls at runtime.

Usage (PowerShell):
    pip install -r requirements.txt
    $env:SPLUNK_PASS="..."
    $env:GEMINI_API_KEY="..."
    python triage.py
"""

import datetime
import ipaddress
import json
import os
import re
import time

import splunklib.client as client
import splunklib.results as results
from google import genai
from google.genai import errors, types

# ---------------------------------------------------------------------------
# Config: secrets come from environment variables so they never live in code
# ---------------------------------------------------------------------------
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "localhost")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))  # Splunk REST API port
SPLUNK_USER = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASS = os.environ["SPLUNK_PASS"]  # required, fails fast if missing
# Models are configurable because providers retire and rate limit them
MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
FALLBACK_MODEL = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-flash-latest")
RETRYABLE_CODES = {429, 500, 503}  # rate limited, server error, overloaded
SECONDS_BETWEEN_CALLS = 13  # stays under free tier requests-per-minute limits
MAX_ROWS_TO_AI = 50  # caps request size per detection

# ---------------------------------------------------------------------------
# Detections: each SPL search answers one question. The API requires the
# leading "search" command. The description gives the AI context.
# ---------------------------------------------------------------------------
DETECTIONS = {
    "Web Vulnerability Scanning": {
        "description": "Sources making an unusually high number of HTTP requests to many unique URIs.",
        "spl": (
            "search index=botsv1 sourcetype=stream:http "
            "| stats count dc(uri) as unique_uris by src_ip, http_user_agent "
            "| where count > 100 | sort -count | head 10"
        ),
    },
    "Web Login Brute Force": {
        "description": "Repeated POST requests containing password fields from the same source.",
        "spl": (
            "search index=botsv1 sourcetype=stream:http http_method=POST form_data=*passwd* "
            "| stats count by src_ip, dest_ip, uri | where count > 20 | sort -count"
        ),
    },
    "IDS Alerts (Suricata)": {
        "description": "Top Suricata IDS signatures and the hosts involved.",
        "spl": (
            "search index=botsv1 sourcetype=suricata event_type=alert "
            "| stats count by alert.signature, alert.severity, src_ip, dest_ip "
            "| sort -count | head 15"
        ),
    },
    "Firewall Top Talkers": {
        "description": "Highest volume source and destination pairs in the perimeter firewall UTM logs.",
        "spl": (
            "search index=botsv1 sourcetype=fgt_utm "
            "| stats count by srcip, dstip, action | sort -count | head 15"
        ),
    },
    "Suspicious Process Execution": {
        "description": "cmd.exe or powershell.exe launches captured by Sysmon (Event ID 1).",
        # Sysmon events are raw XML in this dataset, so fields are extracted with rex
        "spl": (
            'search index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
            "(cmd.exe OR powershell.exe) "
            '| rex "<EventID>(?<EventID>\\d+)</EventID>" '
            "| search EventID=1 "
            "| rex \"Name='Image'>(?<Image>[^<]+)<\" "
            "| rex \"Name='ParentImage'>(?<ParentImage>[^<]+)<\" "
            "| rex \"Name='CommandLine'>(?<CommandLine>[^<]+)<\" "
            '| search Image IN ("*cmd.exe", "*powershell.exe") '
            "| stats count by host, ParentImage, Image, CommandLine | sort -count | head 20"
        ),
    },
}

# ---------------------------------------------------------------------------
# Prompts: the environment, severity rubric, and evidence rules were added
# after reviewing v1 output (invented index names, uncalibrated severity,
# MITRE techniques without supporting evidence)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a Tier 2 SOC analyst reviewing Splunk detection results.

ENVIRONMENT
- All data is in index=botsv1. Never use any other index and never use index=*.
- Sourcetypes and their key fields:
  * stream:http -> src_ip, dest_ip, uri, http_method, http_user_agent, status, form_data
  * suricata -> src_ip, dest_ip, alert.signature, alert.severity
  * fgt_utm -> srcip, dstip, action
  * XmlWinEventLog:Microsoft-Windows-Sysmon/Operational -> host. Other Sysmon fields are raw XML
    and must be extracted with rex, for example: | rex "Name='Image'>(?<Image>[^<]+)<"
- followup_spl must be a runnable search that uses index=botsv1 and only the sourcetypes and fields above.

TOKENS
- Sensitive values are pseudonymized. Use tokens exactly as written; they are swapped back before an analyst reads the report.
- EXT_IP_n = public internet address. INT_IP_n = private internal address.
- HOST_n, USER_n and similar tokens are internal hostnames and usernames.
- Never recommend blocking an INT_IP at the perimeter. Internal hosts are investigated or isolated.

SEVERITY RUBRIC
- Critical: evidence the attacker succeeded (code execution, web shell, malware, confirmed login, data exfiltration).
- High: a targeted attack with no proof of success yet (exploit attempts, brute force against a login).
- Medium: reconnaissance or probing (vulnerability scanning, port scans).
- Low: minor anomalies that are unlikely to be malicious.
- Informational: normal or expected activity with no indicator of a threat.

EVIDENCE RULES
- Only list a MITRE ATT&CK technique if the rows directly show it. Never assume an attack succeeded.
- Use the counts: many requests to one URI suggests brute force or polling; requests spread across
  many unique URIs suggests scanning.
- If the data looks benign, say so and rate it Low or Informational.

Respond ONLY with valid JSON, no preamble and no code fences, in this shape:
{
  "severity": "Critical | High | Medium | Low | Informational",
  "confidence": "High | Medium | Low",
  "summary": "2-3 sentence plain-English summary",
  "attack_narrative": "what the attacker most likely did, step by step",
  "mitre_attack": [{"id": "T1110", "name": "Brute Force"}],
  "recommended_actions": ["specific action 1", "specific action 2"],
  "false_positive_notes": "what could make this benign",
  "followup_spl": "one runnable SPL query an analyst should run next"
}"""

# Final pass that links individual findings into a single attack chain
CORRELATION_PROMPT = """You are a senior SOC analyst. You receive triage findings from several Splunk
detections that ran against the same environment. Connect them into one picture.

- Tokens (EXT_IP_n, INT_IP_n, HOST_n, USER_n) are pseudonymized values. The same token is the same
  entity in every finding.
- The findings have no timestamps, so order stages by attack logic (kill chain), not by time.
- Only link findings when shared tokens or behavior support it. If a link is a guess, put it in open_questions.
- Severity rubric: Critical means evidence the attacker succeeded.

Respond ONLY with valid JSON, no preamble and no code fences, in this shape:
{
  "overall_severity": "Critical | High | Medium | Low | Informational",
  "executive_summary": "3-4 sentences a manager could read",
  "attack_chain": [
    {"stage": "e.g. Reconnaissance", "description": "what happened", "evidence": ["detection names"]}
  ],
  "key_entities": [{"entity": "token", "role": "what this entity did or had done to it"}],
  "priority_actions": ["most important action first"],
  "open_questions": ["what an analyst must verify to confirm this picture"]
}"""

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


# ---------------------------------------------------------------------------
# Pseudonymization: sensitive values are tokenized before leaving the
# environment. One instance per run keeps tokens consistent across
# detections, which is what lets the AI correlate them.
# ---------------------------------------------------------------------------
class Pseudonymizer:
    """Replaces sensitive values with consistent tokens and restores them locally."""

    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    SENSITIVE_FIELDS = ("host", "user", "src_user", "ComputerName")

    def __init__(self):
        self.real_to_token = {}
        self.counters = {}

    def _token(self, value, kind):
        if value not in self.real_to_token:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.real_to_token[value] = f"{kind}_{self.counters[kind]}"
        return self.real_to_token[value]

    @staticmethod
    def _ip_kind(ip):
        # Keeps the network zone (internal vs external) while hiding the address
        try:
            return "INT_IP" if ipaddress.ip_address(ip).is_private else "EXT_IP"
        except ValueError:  # matched the pattern but is not a valid IP
            return "IP"

    def mask_rows(self, rows):
        masked = []
        for row in rows:
            new_row = {}
            for key, value in row.items():
                value = str(value)
                if key in self.SENSITIVE_FIELDS:
                    new_row[key] = self._token(value, key.upper())
                else:
                    new_row[key] = self.IP_RE.sub(
                        lambda m: self._token(m.group(), self._ip_kind(m.group())), value
                    )
            masked.append(new_row)
        return masked

    def unmask(self, text):
        # Longest tokens first so EXT_IP_10 is restored before EXT_IP_1
        for real, token in sorted(self.real_to_token.items(), key=lambda x: -len(x[1])):
            text = text.replace(token, real)
        return text


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------
def run_search(service, spl):
    # earliest_time="0" searches all time; count=0 returns every result
    stream = service.jobs.oneshot(
        spl, output_mode="json", earliest_time="0", latest_time="now", count=0
    )
    # The reader also yields status messages; keep only result rows
    return [r for r in results.JSONResultsReader(stream) if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# AI
# ---------------------------------------------------------------------------
def call_with_retry(ai, prompt, config):
    """Retries the primary model with exponential backoff, then falls back to a second model."""
    last_error = None
    for model in (MODEL, FALLBACK_MODEL):
        wait = 10
        for attempt in range(1, 4):
            try:
                return ai.models.generate_content(model=model, contents=prompt, config=config)
            except errors.APIError as e:
                if getattr(e, "code", None) not in RETRYABLE_CODES:
                    raise  # errors like a retired model will not fix themselves
                last_error = e
                print(f"    {model} busy ({e.code}), attempt {attempt}/3, waiting {wait}s...")
                time.sleep(wait)
                wait *= 2  # exponential backoff: 10s, 20s, 40s
        if model == MODEL:
            print(f"    switching to fallback model {FALLBACK_MODEL}")
    raise last_error


def ask_ai(ai, system_prompt, prompt):
    """Sends one request in JSON mode and returns the parsed response."""
    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
        response_mime_type="application/json",
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    response = call_with_retry(ai, prompt, config)
    text = (response.text or "").strip()
    # Strip markdown code fences if the model adds them anyway
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.M).strip()
    return json.loads(text)


def triage(ai, name, description, rows):
    payload = json.dumps(rows[:MAX_ROWS_TO_AI], indent=1)
    prompt = (
        f"Detection: {name}\nPurpose: {description}\n"
        f"Results ({len(rows)} rows, up to {MAX_ROWS_TO_AI} shown):\n{payload}"
    )
    return ask_ai(ai, SYSTEM_PROMPT, prompt)


def correlate(ai, masked_findings):
    # Receives masked findings, so this request contains no real values either
    prompt = "Triage findings from each detection:\n" + json.dumps(masked_findings, indent=1)
    return ask_ai(ai, CORRELATION_PROMPT, prompt)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def write_correlation(lines, c):
    lines.append(f"## Attack Chain Overview [{c.get('overall_severity')}]\n")
    lines.append(f"{c.get('executive_summary')}\n")
    lines.append("### Attack chain")
    lines.append("_Ordered by attack logic; the detections carry no timestamps._\n")
    for i, step in enumerate(c.get("attack_chain", []), 1):
        evidence = step.get("evidence", [])
        if isinstance(evidence, str):  # model occasionally returns a string, not a list
            evidence = [evidence]
        lines.append(
            f"{i}. **{step.get('stage')}:** {step.get('description')} "
            f"_(evidence: {', '.join(evidence)})_"
        )
    lines.append("\n### Key entities")
    lines += [f"- **{e.get('entity')}:** {e.get('role')}" for e in c.get("key_entities", [])]
    lines.append("\n### Priority actions")
    lines += [f"{i}. {a}" for i, a in enumerate(c.get("priority_actions", []), 1)]
    lines.append("\n### Open questions for the analyst")
    lines += [f"- {q}" for q in c.get("open_questions", [])]
    lines.append("\n---\n\n# Individual Findings\n")


def write_report(findings, correlation, path):
    # .get() is used throughout so a missing field in the AI output cannot crash the report
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f[2].get("severity"), 5))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# AI-Assisted Triage Report\n\nGenerated {now} | {len(findings)} findings\n"]
    lines.append("> AI output is a recommendation. An analyst must validate before acting.\n")

    if correlation:
        write_correlation(lines, correlation)

    for name, row_count, r in findings:
        lines.append(f"## [{r.get('severity')}] {name}")
        lines.append(f"**Confidence:** {r.get('confidence')} | **Matching rows:** {row_count}\n")
        lines.append(f"**Summary:** {r.get('summary')}\n")
        lines.append(f"**Attack narrative:** {r.get('attack_narrative')}\n")
        mitre = ", ".join(f"{t.get('id')} {t.get('name')}" for t in r.get("mitre_attack", []))
        lines.append(f"**MITRE ATT&CK:** {mitre or 'None supported by the data'}\n")
        lines.append("**Recommended actions:**")
        lines += [f"- {a}" for a in r.get("recommended_actions", [])]
        lines.append(f"\n**False positive notes:** {r.get('false_positive_notes')}\n")
        lines.append(f"**Follow-up search:**\n```\n{r.get('followup_spl')}\n```\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ---------------------------------------------------------------------------
# Pipeline: search -> mask -> triage -> unmask -> correlate -> report
# ---------------------------------------------------------------------------
def main():
    service = client.connect(
        host=SPLUNK_HOST, port=SPLUNK_PORT, username=SPLUNK_USER, password=SPLUNK_PASS
    )
    ai = genai.Client()
    pseudo = Pseudonymizer()
    findings = []
    masked_findings = []  # stays masked so the correlation request never sees real values

    for name, d in DETECTIONS.items():
        print(f"[*] {name}")
        rows = run_search(service, d["spl"])
        if not rows:
            print("    no results, skipping")
            continue
        masked = pseudo.mask_rows(rows)
        try:
            result = triage(ai, name, d["description"], masked)
        except (json.JSONDecodeError, errors.APIError) as e:
            print(f"    triage failed: {e}")  # one failed detection does not stop the run
            continue
        masked_findings.append({"detection": name, "matching_rows": len(rows), **result})
        # Real values are restored locally, only after the AI call
        result = json.loads(pseudo.unmask(json.dumps(result)))
        findings.append((name, len(rows), result))
        print(f"    -> {result.get('severity')}")
        time.sleep(SECONDS_BETWEEN_CALLS)

    correlation = None
    if len(masked_findings) >= 2:  # correlation needs at least two findings
        print("[*] Correlating findings into one attack chain")
        try:
            correlation = correlate(ai, masked_findings)
            correlation = json.loads(pseudo.unmask(json.dumps(correlation)))
            print(f"    -> overall {correlation.get('overall_severity')}")
        except (json.JSONDecodeError, errors.APIError) as e:
            print(f"    correlation failed: {e}")

    write_report(findings, correlation, "triage_report.md")
    print(f"\n[+] Report written: triage_report.md ({len(findings)} findings)")


if __name__ == "__main__":
    main()
