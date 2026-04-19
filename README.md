# 🦖 RAPTOR
**Rapid AI Pattern-based Threat Observation and Reporting**

An AI-Driven Hybrid Static Application Security Testing (SAST) Engine designed to eliminate alert fatigue by combining high-speed Regex scanning with Google Gemini AI triage.

## 🚀 Core Architecture
RAPTOR operates on a two-stage hybrid pipeline to ensure high coverage and low noise:
1. **Stage 1 (Detect):** A fast regex engine sweeps source code (`.py`, `.c`, `.cpp`) line-by-line against 17+ strict security rules.
2. **Stage 2 (Analyze & Triage):** Flagged code snippets, along with 5 lines of surrounding context, are batched and sent to Google Gemini (2.5 Flash Lite). The AI evaluates the logic to determine if the flag is a **True Positive** (real threat) or a **False Positive** (safe context/dummy variable).

## ⚙️ Key Features
* **Zero Context Blindness:** Differentiates between actual hardcoded secrets and dummy test variables.
* **Batch AI Processing:** Aggregates all findings into a single JSON payload to prevent API rate-limiting and maximize execution speed (~5s per scan).
* **Enterprise UI & Reporting:** Provides a live, color-coded terminal dashboard (using `rich`) and simultaneously logs a persistent `sast_report.txt` file for audit trails.
* **Plug-and-Play CLI:** Zero complex configurations. Point the tool at a file, and it does the rest.

## 🛠️ Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/Ansa868/RAPTOR-Hybrid-SAST.git](https://github.com/Ansa868/RAPTOR-Hybrid-SAST.git)
   cd RAPTOR-Hybrid-SAST
   ```

2. **Install required dependencies:**
   ```bash
   pip install google-genai colorama rich python-dotenv
   ```

3. **Configure API Key:**
   * Rename the `.env.example` file to `.env`.
   * Open the `.env` file and securely paste your Google Gemini API key:
     `GEMINI_API_KEY=your_actual_api_key_here`

## 💻 Usage
Run the engine via the command line interface against any target file:

```bash
python hybrid_sast.py target_file.py
```
*(The engine will automatically detect the language and load the appropriate rule sets).*
