import re
import os
import json
import sys
from dotenv import load_dotenv
from google import genai
from google.genai import types
from rich.console import Console
from rich.table import Table

# --- INITIALIZATION ---
console = Console()
load_dotenv()
API_KEY = os.getenv("AI_API_KEY", "")
client = genai.Client(api_key=API_KEY)

def load_rules(language):
    filename = 'rules_py.json' if language == "Python" else 'rules_cpp.json'
    if not os.path.exists(filename):
        console.print(f"[bold yellow][!] Warning: {filename} not found.[/bold yellow]")
        return {}
    with open(filename, 'r') as f:
        return json.load(f)

def evaluate_batch_with_ai(findings, language):
    if not API_KEY:
        return [{"id": f["id"], "status": "Error", "reason": "API Key Missing"} for f in findings]

    system_instruction = (
        f"You are a Senior AppSec Auditor. Analyze {language} code snippets flagged by a scanner. "
        "Determine if each item is a 'True Positive' or 'False Positive'. "
        "Respond STRICTLY in a JSON array: [{\"id\": 1, \"status\": \"True Positive\", \"reason\": \"...\"}]."
    )
    
    payload = [{"id": f["id"], "vuln": f["vuln_name"], "code": f["snippet"]} for f in findings]
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
        return json.loads(response.text)
    except Exception as e:
        return [{"id": f["id"], "status": "Error", "reason": str(e)} for f in findings]

def run_hybrid_scan(filepath):
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

    if filepath.endswith(('.cpp', '.c')): detected_lang = "C/C++"
    elif filepath.endswith('.py'): detected_lang = "Python"
    else:
        console.print(f"[bold red][!] Unsupported file: {filepath}[/bold red]")
        return

    active_rules = load_rules(detected_lang)
    console.print(f"[*] Target: [bold white]{filepath}[/bold white] | Rules Loaded: {len(active_rules)}\n")

    try:
        with open(filepath, 'r') as f: lines = f.readlines()
    except Exception as e:
        console.print(f"[bold red][!] Read Error: {e}[/bold red]")
        return

    findings = []
    for line_num, line in enumerate(lines):
        for vuln_name, pattern in active_rules.items():
            if re.search(pattern, line, re.IGNORECASE):
                snippet = "".join(lines[max(0, line_num-2):min(len(lines), line_num+3)])
                findings.append({"id": len(findings)+1, "line_num": line_num+1, "vuln_name": vuln_name, "snippet": snippet})

    if not findings:
        console.print("[bold green][✓] Scan Complete: No suspicious patterns found.[/bold green]")
        return

    with console.status(f"AI Analyzing {len(findings)} findings...", spinner="bouncingBar"):
        ai_results = evaluate_batch_with_ai(findings, detected_lang)
    
    ai_map = {item.get('id'): item for item in ai_results if isinstance(item, dict)}


    # Phase 3: Final Report
    tp, fp = 0, 0
    # File ko loop se bahar open karo taake ye error na aaye
    with open("sast_report.txt", "a") as report_file:
        report_file.write(f"\n--- SCAN REPORT: {filepath} ---\n")
        
        for f in findings:
            res = ai_map.get(f["id"], {"status": "Error", "reason": "No Response"})
            status = res.get('status', 'Error')
            reason = res.get('reason', 'N/A')
            
            if "True" in status:
                tp += 1
                console.print(f"\n[bold white on #163F9C] [!] Scanner Flag: {f['vuln_name']} at Line {f['line_num']} [/bold white on #163F9C]")
                console.print(f"[bold red]► AI Verdict: {status}[/bold red]")
                console.print(f"[bold cyan]   Reason:[/bold cyan] [italic white]{reason}[/italic white]")
                report_file.write(f"[!] {f['vuln_name']} (Line {f['line_num']}) - Verdict: {status}\nReason: {reason}\n")
            else:
                fp += 1
                console.print(f"\n[bold white on #163F9C] [!] Scanner Flag: {f['vuln_name']} at Line {f['line_num']} [/bold white on #163F9C]")
                console.print(f"[bold green]► AI Verdict: {status}[/bold green]")
                console.print(f"[bold cyan]   Reason:[/bold cyan] [italic white]{reason}[/italic white]")
                report_file.write(f"[✓] {f['vuln_name']} (Line {f['line_num']}) - False Positive\nReason: {reason}\n")

    # --- FINAL EXECUTIVE SUMMARY TABLE ---
    console.print("\n")
    summary_table = Table(title="[bold]Scan Complete: Executive Summary[/bold]", show_header=True, header_style="bold cyan")
    summary_table.add_column("Metric", style="dim", width=30)
    summary_table.add_column("Count", justify="right")
    summary_table.add_row("Total Flags Triggered", str(len(findings)))
    summary_table.add_row("[red]True Positives (Critical)[/red]", f"[bold red]{tp}[/bold red]")
    summary_table.add_row("[green]False Positives (Safe)[/green]", f"[bold green]{fp}[/bold green]")
    console.print(summary_table)
    console.print(f"\n[bold cyan][*] Detailed Report saved to -> sast_report.txt[/bold cyan]\n")
  
if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[bold yellow]Usage: python hybrid_sast.py <filename>[/bold yellow]")
    else:
        run_hybrid_scan(sys.argv[1])