import requests, json

OLLAMA_HOST = "http://localhost:11434"

def generate_playbook(alert):
    prompt = f"""
You are a SOC analyst. Input is a JSON alert. 
Output ONLY a JSON object following this schema:

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

ALERT:
{json.dumps(alert)}
    """
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json={
        "model": "mistral:7b",
        "prompt": prompt,
        "options":{"num_threads":16},
        "temperature": 0.0
    })

    full_output = ""
    for line in r.iter_lines():
        if line:
            resp = json.loads(line.decode("utf-8"))
            full_output += resp.get("response", "")

    try:
        return json.loads(full_output)
    except Exception as e:
        print("⚠️ Model did not return valid JSON")
        print(full_output)
        raise e

# Example alert
alert = {
    "alert_id": "ALRT-123",
    "type": "suspicious_login",
    "host": {"hostname": "web-01", "ip": "10.1.1.5"},
    "evidence": [{"type": "log", "data": "ssh failed login 5x"}]
}

playbook = generate_playbook(alert)
print(json.dumps(playbook, indent=2))
