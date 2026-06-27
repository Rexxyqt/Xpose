import os
from core.detector import Detector
from core.entropy import entropy
from core.filesystem import walk_directory

class Scanner:
    def __init__(self, rules, ignore_patterns):
        self.detector = Detector(rules)
        self.ignore_patterns = ignore_patterns

    def scan(self, path):
        findings = []
        for root, dirs, files in walk_directory(path, self.ignore_patterns):
            for f in files:
                filepath = os.path.join(root, f)
                try:
                    with open(filepath, "r", errors="ignore") as fh:
                        for ln, line in enumerate(fh, 1):
                            for match in self.detector.find_secrets(line):
                                findings.append({
                                    "rule": match["rule"],
                                    "severity": match["severity"],
                                    "file": filepath,
                                    "line": ln,
                                    "match": match["match"][:80], # Truncate match for display
                                    "entropy": round(entropy(match["match"]), 2)
                                })
                except Exception:
                    pass  # Ignore files that can't be read
        return findings
