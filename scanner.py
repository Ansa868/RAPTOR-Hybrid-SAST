import re

RULES = {
    # 1. Memory Corruption (Classic C++ issues)
    "Dangerous Function (Buffer Overflow)": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
    
    # 2. OS Command Injection (Hacker runs arbitrary terminal commands)
    "Command Injection Risk": r"\b(system|popen|exec|ShellExecute)\s*\(",
    
    # 3. Hardcoded Secrets (API Keys, DB Passwords)
    "Hardcoded Credential/Secret": r"(password|passwd|api_key|secret_token)\s*=\s*[\"'].+[\"']",
    
    # 4. Weak Cryptography / Bad Randomness (Predictable hashes/numbers)
    "Weak Crypto/Randomness": r"\b(MD5|SHA1|rand)\s*\(",
    
    # 5. Format String Vulnerability (Crashing the program via printf)
    "Format String Vulnerability": r"\b(printf|fprintf)\s*\(\s*[a-zA-Z0-9_]+\s*\)"
}

def scan_file(filepath):
    """Scans a C++ file line-by-line using Regex and extracts surrounding context."""
    print(f"[*] Starting Stage 1 Regex Scan on: {filepath}")
    findings = []
    
    try:
        with open(filepath, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"[!] CRITICAL: File '{filepath}' not found.")
        return []

    # 2. The Iteration Loop
    for line_num, line in enumerate(lines):
        for vuln_name, pattern in RULES.items():
            
            # If the regex pattern matches the current line
            if re.search(pattern, line, re.IGNORECASE):
                
                # 3. Context Extraction (The Masterstroke for Stage 2)
                # Grab 2 lines before and 2 lines after to give the AI context later.
                start_idx = max(0, line_num - 2)
                end_idx = min(len(lines), line_num + 3)
                context_snippet = "".join(lines[start_idx:end_idx])

                # Store the finding
                findings.append({
                    "vuln_type": vuln_name,
                    "line_number": line_num + 1,
                    "flagged_line": line.strip(),
                    "context": context_snippet
                })
    
    return findings

if __name__ == "__main__":
    target_file = "test.cpp"
    results = scan_file(target_file)
    
    # 4. Output formatting
    print(f"\n[+] Scan Complete. Found {len(results)} potential issues:\n")
    for res in results:
        print(f"--- Alert: {res['vuln_type']} ---")
        print(f"Line {res['line_number']}: {res['flagged_line']}")
        print(f"Extracted Context for AI:\n{res['context']}")
        print("-" * 40)
