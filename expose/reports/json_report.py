import json

def save_findings_to_json(findings, output_file="report.json"):
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Saved: {output_file}")
