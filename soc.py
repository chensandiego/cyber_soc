import requests
import json
import time
from typing import List, Dict

OLLAMA_HOST = "http://localhost:11434"

# Model selection thresholds
FAST_MODEL = "deepseek-r1:7b"  # high-frequency alerts
SLOW_MODEL = "llama3:8b"       # complex/high-severity alerts
MAX_TOKENS_PER_ALERT = 128     # limit token usage per alert
NUM_THREADS = 16
NUM_CTX = 2048

# Example alerts
alerts = [
    {"alert_id": "ALRT-101", "type": "suspicious_login", "severity": "low",
     "host": {"hostname": "web-01", "ip": "10.1.1.5"},
     "evidence": [{"type": "log", "data": "ssh failed login 3x"}]},
    {"alert_id": "ALRT-102", "type": "malware_detected", "severity": "high",
     "host": {"hostname": "db-01", "ip": "10.1.1.15"},
     "evidence": [{"type": "log", "data": "suspicious process spawned"}]}
]

def choose_model(alert: Dict) -> str:
    """Select the model based on alert severity/type."""
    if alert.get("severity", "").lower() in ["high", "critical"]:
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

def call_ollama(model: str, prompt: str, max_tokens_per_alert: int, num_threads: int, num_ctx: int):
    """Call Ollama API and return response."""
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json={
        "model": model,
        "prompt": prompt,
        "temperature": 0.0,
        "max_tokens": max_tokens_per_alert * len(alerts),  # batch
        "options": {"num_threads": num_threads, "num_ctx": num_ctx}
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
        return None

def process_alerts(alerts: List[Dict]):
    """Batch alerts and generate playbooks using selected models."""
    # Group alerts by model
    fast_alerts = [a for a in alerts if choose_model(a) == FAST_MODEL]
    slow_alerts = [a for a in alerts if choose_model(a) == SLOW_MODEL]

    results = []

    # Process fast alerts in batch
    if fast_alerts:
        prompt = generate_prompt(fast_alerts)
        res = call_ollama(FAST_MODEL, prompt, MAX_TOKENS_PER_ALERT, NUM_THREADS, NUM_CTX)
        if res:
            results.extend(res)

    # Process slow alerts in batch
    if slow_alerts:
        prompt = generate_prompt(slow_alerts)
        res = call_ollama(SLOW_MODEL, prompt, MAX_TOKENS_PER_ALERT, NUM_THREADS, NUM_CTX)
        if res:
            results.extend(res)

    return results

if __name__ == "__main__":
    start_time = time.time()
    playbooks = process_alerts(alerts)
    elapsed = time.time() - start_time

    print(f"\n✅ Generated {len(playbooks)} playbooks in {elapsed:.2f}s")
    print(json.dumps(playbooks, indent=2))
