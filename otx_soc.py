import requests
import json
import time
from typing import List, Dict

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

POLL_INTERVAL = 30  # seconds

# ---------------- Helper Functions ----------------
def fetch_otx_alerts(limit=10) -> List[Dict]:
    """Fetch alerts from OTX API."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(OTX_API_URL, headers=headers)
    data = r.json()
    alerts = []

    for item in data.get("results", [])[:limit]:
        severity = "medium"  # OTX pulses don’t have numeric priority
        alert = {
            "alert_id": item.get("id") or item.get("pulse_id"),
            "source": "OTX",
            "type": item.get("name"),
            "severity": severity,
            "host": {
                "hostname": item.get("target") or "Unknown",
                "ip": item.get("indicators")[0]["indicator"] if item.get("indicators") else "0.0.0.0"
            },
            "evidence": [{"type": "description", "data": item.get("description") or ""}]
        }
        alerts.append(alert)
    return alerts

def enrich_alert(alert: Dict) -> Dict:
    """Optional enrichment: add GeoIP, asset owner, threat intel."""
    ip = alert["host"]["ip"]
    alert["geo"] = {"country": "Unknown"}  # Replace with real lookup if available
    alert["asset_owner"] = "IT Team"
    alert["threat_intel_score"] = 50  # placeholder score
    return alert

def choose_model(alert: Dict) -> str:
    """Select model based on severity."""
    if alert.get("severity") in ["high", "critical"]:
        return SLOW_MODEL
    return FAST_MODEL

def generate_prompt(alert_batch: List[Dict]) -> str:
    """Prompt for the LLM with exact schema instructions."""
    return f"""
You are a SOC analyst. Process the following alerts and return a JSON array of playbooks.
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
      "command": "string or object",
      "approval_required": true
    }}
  ],
  "explainability": "string"
}}

ALERTS:
{json.dumps(alert_batch)}
"""

def call_ollama(model: str, prompt: str) -> List[Dict]:
    """Call Ollama API for a batch of alerts."""
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json={
        "model": model,
        "prompt": prompt,
        "temperature": 0.0,
        "max_tokens": MAX_TOKENS_PER_ALERT * len(prompt),
        "options": {"num_threads": NUM_THREADS, "num_ctx": NUM_CTX}
    }, stream=True)

    output = ""
    for line in r.iter_lines():
        if line:
            data = json.loads(line.decode("utf-8"))
            output += data.get("response", "")

    try:
        return json.loads(output)
    except Exception:
        print("⚠️ Model output not valid JSON, raw output:")
        print(output)
        return []

def normalize_playbook(raw_playbooks: List[Dict]) -> List[Dict]:
    """Convert LLM output with 'playbook' lists into the expected 'recommended_actions' schema."""
    normalized = []
    for p in raw_playbooks:
        actions = []
        for idx, step in enumerate(p.get("playbook", [])):
            actions.append({
                "id": f"{p['alert_id']}-{idx+1}",
                "type": "investigate",
                "description": step,
                "command": "",
                "approval_required": True
            })
        normalized.append({
            "alert_id": p["alert_id"],
            "classification": p.get("classification", "unknown"),
            "severity": p.get("severity", "medium"),
            "host": p.get("host", {}),
            "recommended_actions": actions,
            "explainability": "Generated from LLM playbook steps"
        })
    return normalized

def process_alerts(alerts: List[Dict]) -> List[Dict]:
    """Enrich, batch by model, and generate playbooks."""
    enriched_alerts = [enrich_alert(a) for a in alerts]

    fast_alerts = [a for a in enriched_alerts if choose_model(a) == FAST_MODEL]
    slow_alerts = [a for a in enriched_alerts if choose_model(a) == SLOW_MODEL]

    results = []

    if fast_alerts:
        prompt = generate_prompt(fast_alerts)
        raw_playbooks = call_ollama(FAST_MODEL, prompt)
        results.extend(normalize_playbook(raw_playbooks))

    if slow_alerts:
        prompt = generate_prompt(slow_alerts)
        raw_playbooks = call_ollama(SLOW_MODEL, prompt)
        results.extend(normalize_playbook(raw_playbooks))

    return results

# ---------------- Main Loop ----------------
if __name__ == "__main__":
    while True:
        otx_alerts = fetch_otx_alerts(limit=10)
        if otx_alerts:
            playbooks = process_alerts(otx_alerts)
            print(f"\n✅ Generated {len(playbooks)} playbooks")
            print(json.dumps(playbooks, indent=2))
        else:
            print("No new alerts")

        time.sleep(POLL_INTERVAL)
