import requests
import json
import time

OLLAMA_HOST = "http://localhost:11434"  # replace if different
MODELS = [
    "mistral:7b",
    "llama3:8b",
    "deepseek-r1:7b"
]

PROMPT = """
You are a SOC analyst. Process the following alert and return a JSON playbook.

ALERT:
{
  "alert_id": "ALRT-123",
  "type": "suspicious_login",
  "host": {"hostname": "web-01", "ip": "10.1.1.5"},
  "evidence": [{"type": "log", "data": "ssh failed login 5x"}]
}
"""

def benchmark_model(model_name, prompt, num_threads=16, num_ctx=2048):
    print(f"\n⏱ Benchmarking model: {model_name}")
    start = time.time()
    r = requests.post(f"{OLLAMA_HOST}/api/generate", json={
        "model": model_name,
        "prompt": prompt,
        "temperature": 0.0,
        "max_tokens": 256,
        "options": {
            "num_threads": num_threads,
            "num_ctx": num_ctx
        }
    }, stream=True)

    output = ""
    for line in r.iter_lines():
        if line:
            data = json.loads(line.decode("utf-8"))
            output += data.get("response", "")

    elapsed = time.time() - start
    tokens_generated = len(output.split())  # rough token approximation
    tokens_per_sec = tokens_generated / elapsed

    print(f"Elapsed time: {elapsed:.2f}s")
    print(f"Approx tokens generated: {tokens_generated}")
    print(f"Tokens/sec: {tokens_per_sec:.2f}")
    return tokens_per_sec

if __name__ == "__main__":
    results = {}
    for model in MODELS:
        tps = benchmark_model(model, PROMPT)
        results[model] = tps

    print("\n📊 Summary (tokens/sec):")
    for model, tps in results.items():
        print(f"{model}: {tps:.2f} tokens/sec")
