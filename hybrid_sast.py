import re
import os
import json
import sys
import time
from dotenv import load_dotenv
from colorama import init
from google import genai
from google.genai import types

# --- UI LIBRARIES ---
from rich.console import Console
from rich.table import Table

# --- 1. CONFIGURATION & SETUP ---
# Initialize terminal colors and rich console for UI rendering
init(autoreset=True)
console = Console()

# Load environment variables securely
load_dotenv()
API_KEY = os.getenv("AI_API_KEY")
if not API_KEY:
    console.print("[bold red][!] CRITICAL ERROR: API_KEY not found in .env file![/bold red]")
    sys.exit(1)

# Initialize the AI Client
client = genai.Client(api_key=API_KEY)

# --- 2. SECURITY RULE SETS ---
# Dictionaries containing RegEx patterns for common vulnerabilities
C_CPP_RULES = {
    "Dangerous Function (Buffer Overflow)": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
    "Command Injection Risk": r"\b(system|popen|exec|ShellExecute)\s*\(",
    "Hardcoded Credential/Secret": r"(password|passwd|api_key|secret_token)\s*=\s*[\"'].+[\"']",
    "Weak Crypto/Randomness": r"\b(MD5|SHA1|rand)\s*\(",
    "Format String Vulnerability": r"\b(printf|fprintf)\s*\(\s*[a-zA-Z0-9_]+\s*\)",
    "SQL Injection Risk": r"(SELECT|UPDATE|INSERT|DELETE).*['\"]\s*\+\s*[a-zA-Z0-9_]+",
    "Memory Leak Risk (Manual Allocation)": r"\b(malloc|calloc|realloc)\s*\(",
    "Use After Free Risk": r"\bfree\s*\(\s*[a-zA-Z0-9_]+\s*\)",
    "Insecure File Access": r"\bfopen\s*\("
}

PYTHON_RULES = {
    "Command Injection Risk": r"\b(os\.system|subprocess\.Popen|eval|exec)\s*\(",
    "Hardcoded Credential/Secret": r"(password|passwd|api_key|SECRET_KEY)\s*=\s*[\"'].+[\"']",
    "Weak Crypto/Hashing": r"\b(hashlib\.md5|random\.)",
    "SQL Injection Risk": r"(SELECT|UPDATE|INSERT|DELETE).*['\"]\s*\+\s*[a-zA-Z0-9_]+",
    "Insecure Deserialization": r"\b(pickle\.loads|yaml\.load)\s*\(",
    "Insecure Network Request (No SSL)": r"\brequests\.(get|post|put|delete).*verify\s*=\s*False",
    "Debug Mode Enabled (Prod Risk)": r"app\.run\s*\(.*debug\s*=\s*True\)",
    "Weak JWT Token Algorithm": r"jwt\.encode\s*\(.*algorithm\s*=\s*['\"]none['\"]"
}

# --- 3. BATCH AI PROCESSING ENGINE ---
def evaluate_batch_with_ai(findings, language):
    """
    Takes a list of vulnerability findings and evaluates them in a single API call.
    This prevents API rate limiting and eliminates console spam.
    """
    system_instruction = f"""
    You are a strict Application Security Engineer. 
    Analyze the following JSON list of potential {language} vulnerabilities flagged by a RegEx scanner.
    Determine if each item is a 'True Positive' (actual exploitable risk) or a 'False Positive' (safe context).
    Respond STRICTLY in a valid JSON array format. Do not add markdown or extra text.
    Format requirements:
    [
        {{"id": 1, "status": "True Positive", "reason": "1 short sentence explaining why."}},
        {{"id": 2, "status": "False Positive", "reason": "1 short sentence explaining why."}}
    ]
    """
    
    # Prepare the payload for Gemini
    payload = []
    for f in findings:
        payload.append({
            "id": f["id"],
            "vulnerability_type": f["vuln_name"],
            "code_snippet": f["snippet"]
        })
        
    prompt = f"Analyze these findings:\n{json.dumps(payload, indent=2)}"
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash-lite',
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                temperature=0.1
            )
        )
        # Parse the JSON array returned by the AI
        return json.loads(response.text)
    except Exception as e:
        # Fallback error mapping in case of API failure
        return [{"id": f["id"], "status": "Error", "reason": str(e)} for f in findings]

# --- 4. CORE SCANNER LOGIC ---
def run_hybrid_scan(filepath):
    """Main execution function that handles file reading, regex sweeping, and AI triage."""
    
    # Render the RAPTOR Banner
    banner = """
    [bold red]██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ [/bold red]
    [bold red]██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗[/bold red]
    [bold red]██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝[/bold red]
    [bold cyan]██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗[/bold cyan]
    [bold cyan]██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║[/bold cyan]
    [bold cyan]╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝[/bold cyan]
    [bold yellow] [+] RAPTOR: Rapid AI Pattern-based Threat Observation and Reporting [+][/bold yellow]
    [bold yellow] [+] Developed by: Ansa [+][/bold yellow]
    """
    console.print(banner)
    console.print(f"[bold cyan][*] Starting AI-Assisted Scan on: {filepath}...[/bold cyan]\n")
    
    # Determine the target language and load appropriate rules
    if filepath.endswith('.cpp') or filepath.endswith('.c'):
        active_rules = C_CPP_RULES
        detected_lang = "C/C++"
    elif filepath.endswith('.py'):
        active_rules = PYTHON_RULES
        detected_lang = "Python"
    else:
        console.print(f"[bold red][!] Unsupported file format: {filepath}[/bold red]")
        return

    console.print(f"[bold magenta][*] Language Detected: {detected_lang}[/bold magenta]")
    console.print(f"[bold magenta][*] Loading {len(active_rules)} Security Rules...[/bold magenta]\n")

    # Initialize persistent reporting
    report_filename = "sast_report.txt"
    with open(report_filename, "a") as log_file:
        log_file.write(f"\n=== Target File: {filepath} ({detected_lang}) ===\n")

    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        console.print(f"[bold red][!] Target file '{filepath}' not found.[/bold red]")
        return

    # Track metrics
    true_pos_count = 0
    false_pos_count = 0
    error_count = 0

    # Phase 1: Regex Sweeping (Collect all findings without calling AI yet)
    findings = []
    for line_num, line in enumerate(lines):
        for vuln_name, pattern in active_rules.items():
            if re.search(pattern, line, re.IGNORECASE):
                # Extract 5 lines of context around the flagged line
                start_idx = max(0, line_num - 2)
                end_idx = min(len(lines), line_num + 3)
                context_snippet = "".join(lines[start_idx:end_idx])
                
                findings.append({
                    "id": len(findings) + 1,
                    "line_num": line_num + 1,
                    "vuln_name": vuln_name,
                    "snippet": context_snippet
                })

    # If no vulnerabilities are found, exit gracefully
    if not findings:
        console.print("[bold green][*] Scan complete. No suspicious patterns detected.[/bold green]\n")
        return

    # Phase 2: Batch AI Evaluation (One single API call for the entire file)
    with console.status(f"[bold cyan]Analyzing {len(findings)} flagged patterns with AI...", spinner="bouncingBar"):
        # UI/UX Enhancement: Intentional 3-second delay to ensure the animation is visible
        time.sleep(3) 
        ai_results = evaluate_batch_with_ai(findings, detected_lang)
        
    # Map AI results back to their IDs for O(1) lookup
    ai_results_map = {item.get('id'): item for item in ai_results if isinstance(item, dict)}

    # Phase 3: Unified Reporting
    for f in findings:
        console.print(f"\n[bold white on red] [!] Scanner Flag: {f['vuln_name']} at Line {f['line_num']} [/bold white on red]")
        
        # Retrieve the specific AI verdict for this finding
        ai_verdict = ai_results_map.get(f["id"], {})
        status = ai_verdict.get('status', 'Error')
        reason = ai_verdict.get('reason', 'No specific reason provided by AI.')
        
        # Determine output formatting based on status
        if "True Positive" in status:
            true_pos_count += 1
            console.print(f"[bold red]► AI Verdict: {status}[/bold red]")
            console.print(f"[red]  Reason: {reason}[/red]")
        elif "False Positive" in status:
            false_pos_count += 1
            console.print(f"[bold green]► AI Verdict: {status}[/bold green]")
            console.print(f"[green]  Reason: {reason}[/green]")
        else:
            error_count += 1
            console.print(f"[bold yellow]► AI Verdict: {status}[/bold yellow]")
            console.print(f"[yellow]  Reason: {reason}[/yellow]")

        # Append structured data to the text report
        with open(report_filename, "a") as log_file:
            log_file.write(f"[!] Scanner Flag: {f['vuln_name']} at Line {f['line_num']}\n")
            log_file.write(f"[+] AI Verdict: {status}\n")
            log_file.write(f"    Reason: {reason}\n")
            log_file.write("-" * 60 + "\n")

    # --- FINAL EXECUTIVE SUMMARY ---
    console.print("\n")
    summary_table = Table(title="[bold]Scan Complete: Executive Summary[/bold]", show_header=True, header_style="bold cyan")
    summary_table.add_column("Metric", style="dim", width=30)
    summary_table.add_column("Count", justify="right")

    summary_table.add_row("Total Lines Scanned", str(len(lines)))
    summary_table.add_row("Total Flags Triggered", str(len(findings)))
    summary_table.add_row("[red]True Positives (Critical)[/red]", f"[bold red]{true_pos_count}[/bold red]")
    summary_table.add_row("[green]False Positives (Safe)[/green]", f"[bold green]{false_pos_count}[/bold green]")
    
    if error_count > 0:
        summary_table.add_row("[yellow]AI Errors / Timeouts[/yellow]", f"[bold yellow]{error_count}[/bold yellow]")

    console.print(summary_table)
    console.print(f"\n[bold cyan][*] Detailed Report saved to -> {report_filename}[/bold cyan]\n")

# --- 5. CLI ENTRY POINT ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("\n[bold white on red] [!] Execution Error: Target file missing. [/bold white on red]")
        console.print("[bold yellow][*] Usage: python hybrid_sast.py <filename>[/bold yellow]")
    else:
        target_file = sys.argv[1]
        run_hybrid_scan(target_file)