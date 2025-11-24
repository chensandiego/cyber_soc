import requests
import json
import time
from typing import List, Dict
import re
# ---------------- OTX CONFIG ----------------
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_API_KEY = "5e330b0bb672d399743d72202730638597668f4f17885d16c35b68fdfece6e3f"

# ---------------- LLM CONFIG ----------------
OLLAMA_HOST = "http://localhost:11434"
FAST_MODEL = "deepseek-r1:7b"  # high-frequency alerts
SLOW_MODEL = "llama3:8b"       # high-severity/complex alerts
MAX_TOKENS_PER_ALERT = 128
NUM_THREADS = 16
NUM_CTX = 2048

POLL_INTERVAL = 30 




# ---------------- Helper Functions ----------------
def map_severity(tags: List[str]) -> str:
    """Map OTX tags to severity level."""
    if not tags:
        return "medium"
    tags = [t.lower() for t in tags]
    if any(t in tags for t in ["critical", "apt", "ransomware", "zeroday", "exploit"]):
        return "high"
    elif any(t in tags for t in ["malware", "trojan", "phishing", "c2", "data theft"]):
        return "medium"
    elif any(t in tags for t in ["suspicious", "test", "low"]):
        return "low"
    return "medium"

def fetch_otx_alerts(limit=10) -> List[Dict]:
    """Fetch alerts from OTX API."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(OTX_API_URL, headers=headers, timeout=30)
    data = r.json()
    alerts = []

    for item in data.get("results", [])[:limit]:
        severity = map_severity(item.get("tags", []))
        indicator = item.get("indicators")[0]["indicator"] if item.get("indicators") else "0.0.0.0"

        alert = {
            "alert_id": item.get("id") or item.get("pulse_id"),
            "source": "OTX",
            "type": item.get("name"),
            "severity": severity,
            "host": {
                "hostname": item.get("author_name") or "Unknown",
                "ip": indicator
            },
            "evidence": [{"type": "description", "data": item.get("description") or ""}]
        }
        alerts.append(alert)
    return alerts

def enrich_alert(alert: Dict) -> Dict:
    """Optional enrichment: add GeoIP, asset owner, threat intel."""
    alert["geo"] = {"country": "Unknown"}
    alert["asset_owner"] = "IT Team"
    alert["threat_intel_score"] = 50
    return alert

def choose_model(alert: Dict) -> str:
    """Choose LLM model based on severity."""
    if alert.get("severity") in ["high", "critical"]:
        return SLOW_MODEL
    return FAST_MODEL

def generate_prompt(alert_batch: List[Dict]) -> str:
    """Generate structured JSON-only prompt for LLM."""
    example_output = [
        {
            "alert_id": "ALERT123",
            "classification": "malware",
            "severity": "medium",
            "host": {"hostname": "testhost", "ip": "1.2.3.4"},
            "recommended_actions": [
                {
                    "id": "1",
                    "type": "investigate",
                    "description": "Investigate alert",
                    "command": "",
                    "approval_required": True
                }
            ],
            "explainability": "Generated from alert"
        }
    ]

    return f"""
You are a SOC analyst. Process the following alerts and return ONLY a valid JSON array of playbooks.
Do NOT include explanations, commentary, <think>, or extra text.

Each playbook must follow this schema exactly:

{{
  "alert_id": "string",
  "classification": "bruteforce|malware|phishing|detection|unknown",
  "severity": "low|medium|high|critical",
  "host": {{
      "hostname": "string",
      "ip": "string"
  }},
  "recommended_actions": [
    {{
      "id": "string",
      "type": "investigate|isolate|block_ip|notify|ticket",
      "description": "string",
      "command": "string",
      "approval_required": true
    }}
  ],
  "explainability": "string"
}}

Here is an example of the expected JSON output:
{json.dumps(example_output, indent=2)}

ALERTS:
{json.dumps(alert_batch)}
"""

def safe_parse_json(raw_output: str) -> List[Dict]:
    """Extract JSON array from messy LLM output."""
    # Remove <think> and other non-JSON
    raw_output = re.sub(r"<think>.*?</think>", "", raw_output, flags=re.DOTALL)
    match = re.search(r'(\[.*\])', raw_output, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception as e:
            print(f"⚠️ JSON parsing failed: {e}")
    return []

def call_ollama(model: str, prompt: str) -> List[Dict]:
    """Call Ollama API and safely parse JSON output."""
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json={
        "model": model,
        "prompt": prompt,
        "temperature": 0.0,
        "max_tokens": MAX_TOKENS_PER_ALERT * 20,
        "options": {"num_threads": NUM_THREADS, "num_ctx": NUM_CTX}
    }, stream=True)

    output_lines = []
    for line in r.iter_lines():
        if line:
            try:
                data = json.loads(line.decode("utf-8"))
                if "response" in data:
                    output_lines.append(data["response"])
            except Exception:
                output_lines.append(line.decode("utf-8"))

    output_str = "".join(output_lines)
    return safe_parse_json(output_str)

def process_alerts(alerts: List[Dict]) -> List[Dict]:
    """Main pipeline: enrich alerts, select model, generate playbooks."""
    enriched_alerts = [enrich_alert(a) for a in alerts]
    results = []

    fast_alerts = [a for a in enriched_alerts if choose_model(a) == FAST_MODEL]
    slow_alerts = [a for a in enriched_alerts if choose_model(a) == SLOW_MODEL]

    if fast_alerts:
        prompt = generate_prompt(fast_alerts)
        results.extend(call_ollama(FAST_MODEL, prompt))

    if slow_alerts:
        prompt = generate_prompt(slow_alerts)
        results.extend(call_ollama(SLOW_MODEL, prompt))

    return results

# ---------------- Main Loop ----------------
if __name__ == "__main__":
    while True:
        otx_alerts = fetch_otx_alerts(limit=5)
        if otx_alerts:
            playbooks = process_alerts(otx_alerts)
            print(f"\n✅ Generated {len(playbooks)} playbooks")
            print(json.dumps(playbooks, indent=2))
        else:
            print("No new alerts")

        time.sleep(POLL_INTERVAL)
