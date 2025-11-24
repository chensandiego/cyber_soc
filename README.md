# AI-Powered SOC Analyst using Local LLMs

This project demonstrates the use of local Large Language Models (LLMs) to automate the analysis of security alerts and generate actionable response playbooks. It functions as a proof-of-concept for an AI-powered Security Operations Center (SOC) analyst.

The system fetches threat intelligence data from AlienVault OTX, processes it, and uses different LLMs based on alert severity to recommend actions.

## Core Functionality

- **Threat Intelligence Ingestion**: Fetches live threat data (pulses) from AlienVault OTX.
- **Dynamic Model Selection**: Uses a dual-model approach to balance speed and analytical depth:
    - A **fast model** (e.g., `deepseek-r1:7b`) for high-frequency, low-severity alerts.
    - A **slower, more powerful model** (e.g., `llama3:8b`) for complex or high-severity threats.
- **Automated Playbook Generation**: Generates structured JSON playbooks containing:
    - Alert classification (e.g., `malware`, `bruteforce`).
    - Recommended actions (e.g., `isolate`, `block_ip`, `investigate`).
    - An explanation for the recommendation.
- **Resilient Parsing**: Includes robust parsing to safely extract valid JSON from the LLM's output, even if it includes extraneous text.
- **Benchmarking**: Provides a tool to measure the performance (tokens/second) of different LLMs.

---

## Scripts Overview

- **`otx_soc_v2.py`**
  This is the main, most advanced script. It runs in a continuous loop, fetches alerts from OTX, maps their severity, and uses the dual-model LLM approach to generate response playbooks. It features robust prompt engineering and output parsing.

- **`otx_soc.py` & `alienvalut_soc.py`**
  These are earlier versions of the OTX integration script. They provide the foundational logic but are less refined than `v2`. `alienvalut_soc.py` also contains a placeholder for integrating with OSSIM.

- **`soc.py`**
  A basic script that demonstrates the core playbook generation logic using a hardcoded list of alerts. It's a good starting point for understanding the prompt and model-calling flow.

- **`benchmark.py`**
  A utility to benchmark the performance of the LLMs configured in the project. It helps in evaluating which models are best suited for the fast and slow roles.

- **`test.py`**
  A simple script for running a single test case against a model to verify the output format.

---

## Setup & Usage

### Prerequisites

1.  **Python 3**: Make sure you have Python 3 installed.
2.  **Ollama**: Install and run [Ollama](https://ollama.com/) on your local machine.
3.  **LLMs**: Pull the required models using the Ollama CLI.
    ```bash
    ollama pull deepseek-r1:7b
    ollama pull llama3:8b
    ollama pull mistral:7b
    ```
4.  **Python Libraries**: Install the necessary Python packages.
    ```bash
    pip install requests
    ```

### Configuration

Open the `otx_soc_v2.py` file (or other scripts) and set your AlienVault OTX API key:

```python
# ---------------- OTX CONFIG ----------------
OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE" # <--- EDIT THIS
```

You can also change the models used for `FAST_MODEL` and `SLOW_MODEL` if you wish.

### Running the System

To start the continuous monitoring process, run the `otx_soc_v2.py` script:

```bash
python otx_soc_v2.py
```

The script will start fetching alerts and printing the generated JSON playbooks to the console.

To benchmark the models, run:
```bash
python benchmark.py
```
