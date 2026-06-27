import os

def print_findings_to_console(findings, target=None, base_path=None):
    print("="*50)
    print(" SecretScan Report")
    if target:
        print(f" Target: {target}")
    print("="*50)
    
    if not findings:
        print("\n  [!] No secrets found.\n")
    else:
        for r2 in findings:
            print(f"[{r2['severity']}] {r2['rule']}")
            file_path = r2['file']
            if base_path:
                file_path = os.path.relpath(r2['file'], base_path)
            print(f"  File : {file_path}")
            print(f"  Line : {r2['line']}")
            print(f"  Match: {r2['match']}")
            print()
        print(f"Secrets Found: {len(findings)}")
