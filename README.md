# Expose

```
____  ___                                
\   \/  /______    ____   ______  ____   
 \     / \____ \  /  _ \ /  ___/_/ __ \  
 /     \ |  |_> >(  <_> )\___ \ \  ___/  
/___/\  \|   __/  \____//____  > \___  > 
      \_/|__|                \/      \/ 
```

Secret scanner that walks a directory (or a cloned GitHub repo) and matches configured regex rules.

**What is this for?**
- Helps find potential **secrets** in your codebase (e.g., API keys, DB credentials, etc.).
- Scans a local folder or a remote GitHub repo and generates a **report.json** of findings.



## Project layout (important)
- Entrypoint script: **`xpose.py`** (at repo root)
- Rules live under: **`expose/rules/`**

## Setup (Windows)
1. Install **Git** (if needed)
   - https://git-scm.com/download/win

2. Install **Python 3.8+**
   - https://www.python.org/downloads/windows/

3. Install dependencies
   ```bat
   cd /d "c:\Users\rexje\OneDrive\Documents\Xpose"
   pip install -r expose\requirements.txt
   ```

## Running the tool
### Interactive menu (recommended)
```bat
python -u xpose.py
```

### Direct CLI commands
Local scan:
```bat
python -u xpose.py scan .
python -u xpose.py scan C:\path\to\dir
```

Remote scan (GitHub):
```bat
python -u xpose.py remote https://github.com/user/repo
python -u xpose.py remote https://github.com/user/repo --tree
```

### Output
Each run writes findings to:
- **`report.json`** in the current working directory.

## Troubleshooting
### `ModuleNotFoundError: No module named 'xpose.core'; 'xpose' is not a package`
This happens when the script tries to import using the wrong package name. In this project, modules are under the **`expose/`** directory.

✅ Use the provided entrypoint:
```bat
python -u xpose.py scan .
```

## Notes
- Scanning includes any readable files under the target path.
- Unreadable files are skipped silently.

