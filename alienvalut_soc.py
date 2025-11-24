import requests
import json
import time
from typing import List, Dict

# ---------------- OSSIM CONFIG ----------------
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

OTX_API_KEY = "get otx api key"
POLL_INTERVAL = 30  # seconds

# ---------------- LLM CONFIG ----------------
OLLAMA_HOST = "http://localhost:11434"
FAST_MODEL = "deepseek-r1:7b"  # high-frequency alerts
SLOW_MODEL = "llama3:8b"       # complex/high-severity alerts
MAX_TOKENS_PER_ALERT = 128
NUM_THREADS = 16
NUM_CTX = 2048

# ---------------- Helper Functions ----------------
def fetch_ossim_alerts(limit=10) -> List[Dict]:
    """Fetch open alerts from OSSIM API and convert to LLM JSON format."""
    headers = {
        "Accept": "application/json",
        "X-API-KEY": OTX_API_KEY
    }
    params = {"limit": limit, "status": "open"}
    r = requests.get(OTX_API_URL, headers=headers, params=params, verify=False)
    data = r.json()
    alerts = []

    for item in data.get("data", []):
        # Map OSSIM priority to low/medium/high/critical
        priority = item.get("priority", 3)
        if priority <= 3:
            severity = "low"
        elif priority <= 6:
            severity = "medium"
        elif priority <= 8:
            severity = "high"
        else:
            severity = "critical"

        alert = {
            "alert_id": item.get("id"),
            "type": item.get("plugin_name") or item.get("type"),
            "severity": severity,
            "host": {"hostname": item.get("hostname"), "ip": item.get("src_ip")},
            "evidence": [{"type": "log", "data": item.get("full_log")}]
        }
        alerts.append(alert)
    return alerts



def fetch_otx_alerts(limit=10) -> List[Dict]:
    """Fetch alerts from OTX API."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    r = requests.get(OTX_API_URL, headers=headers)
    data = r.json()
    alerts = []

    for item in data.get("results", [])[:limit]:
        severity = "medium"  # OTX pulses don’t have numeric priority, adjust if needed
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
    # Example: fake enrichment
    alert["geo"] = {"country": "Unknown"}  # replace with real lookup
    alert["asset_owner"] = "IT Team"
    alert["threat_intel_score"] = 50  # placeholder
    return alert

def choose_model(alert: Dict) -> str:
    """Select model based on severity."""
    if alert.get("severity") in ["high", "critical"]:
        return SLOW_MODEL
    return FAST_MODEL

def generate_prompt(alert_batch: List[Dict]) -> str:
    """Create a batched prompt for multiple alerts."""
    return f"""
You are a SOC analyst. Process the following alerts and return a JSON array of playbooks.
Each playbook must follow this schema:

{{
  "alert_id": "string",
  "classification": "bruteforce|malware|phishing|unknown",
  "severity": "low|medium|high|critical",
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

def process_alerts(alerts: List[Dict]) -> List[Dict]:
    """Batch alerts by model, enrich them, and generate playbooks."""
    enriched_alerts = [enrich_alert(a) for a in alerts]

    fast_alerts = [a for a in enriched_alerts if choose_model(a) == FAST_MODEL]
    slow_alerts = [a for a in enriched_alerts if choose_model(a) == SLOW_MODEL]

    results = []

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
        alerts = fetch_otx_alerts(limit=10)
        if alerts:
            playbooks = process_alerts(alerts)
            print(f"\n✅ Generated {len(playbooks)} playbooks")
            print(json.dumps(playbooks, indent=2))
        else:
            print("No new alerts")

        time.sleep(POLL_INTERVAL)
