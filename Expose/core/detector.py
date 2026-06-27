import re

class Detector:
    def __init__(self, rules):
        self.rules = [(r["name"], re.compile(r["pattern"]), r["severity"]) for r in rules["rules"]]

    def find_secrets(self, line):
        findings = []
        for name, pattern, severity in self.rules:
            for match in pattern.finditer(line):
                findings.append({
                    "rule": name,
                    "severity": severity,
                    "match": match.group(0),
                    "start": match.start(),
                    "end": match.end()
                })
        return findings
