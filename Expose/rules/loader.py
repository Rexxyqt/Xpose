import os
import json

def load_rules(rules_dir):
    all_rules = []
    for filename in os.listdir(rules_dir):
        if filename.endswith(".json") and filename != "ignore.json":
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, "r") as f:
                rules = json.load(f)
                all_rules.extend(rules)
    return {"rules": all_rules}

def load_ignore_patterns(rules_dir):
    filepath = os.path.join(rules_dir, "ignore.json")
    with open(filepath, "r") as f:
        data = json.load(f)
        return set(data.get("ignore_patterns", []))
