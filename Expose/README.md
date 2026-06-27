# Expose

```
____  ___                                
\   \/  /______    ____   ______  ____   
 \     / \____ \  /  _ \ /  ___/_/ __ \  
 /     \ |  |_> >(  <_> )\___ \ \  ___/  
/___/\  \|   __/  \____//____  > \___  > 
      \_/|__|                \/      \/ 
```

## Setup (Windows & Linux)

1. **Install Git** (if not already installed)  
   - Windows: https://git-scm.com/download/win  
   - Linux: `sudo apt-get install git` (Debian/Ubuntu) or equivalent for your distro.

2. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/Expose.git   # replace with actual repo URL
   cd Expose
   ```

3. **Install Python 3.8+**  
   - Windows: https://www.python.org/downloads/windows/  
   - Linux: usually pre‑installed; otherwise `sudo apt-get install python3`.

4. **Install required Python packages**  
   ```bash
   pip install -r requirements.txt
   ```
   (`requirements.txt` contains `colorama` and `requests`.)

## Running the tool

### Interactive menu (recommended)

```bash
python expose.py
```
You will see the ASCII banner above and a menu:
```
Select an option:
  1) Scan Local Directory
  2) Scan Remote GitHub
  3) Help
  4) Exit
Enter choice [1-4]:
```
- Choose **1** to scan a local folder (enter path or press Enter for `.`).
- Choose **2** to scan a remote GitHub repo (enter URL, then answer y/N to show the directory tree first).

### Direct CLI commands

```bash
# Scan a local directory (Windows PowerShell / CMD or Linux bash)
python expose.py scan               # scans current directory (.)
python expose.py scan C:\path\to\dir   # Windows example
python expose.py scan /path/to/dir     # Linux example

# Scan a remote GitHub repository
python expose.py remote https://github.com/user/repo
python expose.py remote https://github.com/user/repo --tree   # show tree before scanning
```

After each scan, a `report.json` file is written in the current directory.
