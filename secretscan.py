
#!/usr/bin/env python3
import os,re,json,argparse,math
from collections import Counter

DEFAULT_RULES={
 "rules":[
  {"name":"OpenAI API Key","pattern":r"sk-[A-Za-z0-9]{20,55}","severity":"HIGH"},
  {"name":"GitHub PAT","pattern":r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}","severity":"HIGH"},
  {"name":"AWS Access Key","pattern":r"AKIA[0-9A-Z]{16}","severity":"HIGH"},
  {"name":"Google/Firebase/Gemini API Key","pattern":r"AIza[0-9A-Za-z\-_]{35}","severity":"HIGH"},
  {"name":"Anthropic API Key","pattern":r"sk-ant-[A-Za-z0-9\-_]{20,}","severity":"HIGH"},
  {"name":"OpenRouter API Key","pattern":r"sk-or-v1-[A-Za-z0-9]{20,}","severity":"HIGH"},
  {"name":"Discord Token","pattern":r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}","severity":"HIGH"},
  {"name":"Slack Token","pattern":r"xox[a-zA-Z]-[A-Za-z0-9-]{10,48}","severity":"HIGH"},
  {"name":"JWT","pattern":r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}","severity":"MEDIUM"},
  {"name":"Private Key","pattern":r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----","severity":"CRITICAL"},
  {"name":"Mongo URI","pattern":r"mongodb(?:\+srv)?://[^ \n]+","severity":"HIGH"},
  {"name":"Postgres URI","pattern":r"postgres(?:ql)?://[^ \n]+","severity":"HIGH"},
  {"name":"MySQL URI","pattern":r"mysql://[^ \n]+","severity":"HIGH"},
  {"name":"Generic API Key","pattern":r"(?i)(?:api[_-]?key|api[_-]?secret)\s*[:=]\s*[\"'][^\"']{16,}[\"']","severity":"MEDIUM"},
 ]
}
IGNORE={".git","node_modules","venv","__pycache__","dist","build",".idea",".vscode"}

def entropy(s):
    if not s:return 0
    c=Counter(s);l=len(s)
    return -sum((n/l)*math.log2(n/l) for n in c.values())

def scan(path):
    findings=[]
    rules=[(r["name"],re.compile(r["pattern"]),r["severity"]) for r in DEFAULT_RULES["rules"]]
    for root,dirs,files in os.walk(path):
        dirs[:]=[d for d in dirs if d not in IGNORE]
        for f in files:
            fp=os.path.join(root,f)
            try:
                with open(fp,"r",errors="ignore") as fh:
                    for ln,line in enumerate(fh,1):
                        for name,pat,sev in rules:
                            for m in pat.finditer(line):
                                findings.append({
                                  "rule":name,"severity":sev,"file":fp,
                                  "line":ln,"match":m.group(0)[:80],
                                  "entropy":round(entropy(m.group(0)),2)
                                })
            except: pass
    return findings

def main():
    ap=argparse.ArgumentParser(prog="secretscan")
    sub=ap.add_subparsers(dest="cmd")
    s=sub.add_parser("scan")
    s.add_argument("path",nargs="?",default=".")
    a=ap.parse_args()
    if a.cmd=="scan":
        res=scan(a.path)
        print("="*50)
        print(" SecretScan Report")
        print("="*50)
        for r in res:
            print(f"[{r['severity']}] {r['rule']}")
            print(f"  File : {r['file']}")
            print(f"  Line : {r['line']}")
            print(f"  Match: {r['match']}")
            print()
        with open("report.json","w") as f:
            json.dump(res,f,indent=2)
        print(f"Secrets Found: {len(res)}")
        print("Saved: report.json")
    else:
        ap.print_help()
if __name__=="__main__":
    main()
