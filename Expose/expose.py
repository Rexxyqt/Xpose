import os
import re
import json
import math
import tempfile
import shutil
import subprocess
import requests
import argparse
import sys
import io
from collections import Counter
import colorama
from colorama import Fore, Style
colorama.init(autoreset=True)

from core.scanner import Scanner
from core.entropy import entropy
from rules.loader import load_rules, load_ignore_patterns
from core.tree import show_tree


# ASCII art banner
BANNER = r'''
____  ___                                
\   \/  /______    ____   ______  ____   
 \     / \____ \  /  _ \ /  ___/_/ __ \  
 /     \ |  |_> >(  <_> )\___ \ \  ___/  
/___/\  \|   __/  \____//____  > \___  > 
      \_/|__|                \/      \/                                        
'''


def parse_github_url(url):
    """Parse GitHub URL to owner/repo format.

    Args:
        url (str): GitHub repository URL.

    Returns:
        str: Owner/Repository string.

    Raises:
        ValueError: If URL is not a valid GitHub repository URL.
    """
    if url.endswith(".git"):
        url = url[:-4]
    url = url.rstrip("/")

    patterns = [
        r"github\.com[:/]([^/]+)/([^/]+)",
        r"git@github\.com:([^/]+)/([^/]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"

    if re.match(r'^[\w.-]+/[\w.-]+$', url):
        return url

    raise ValueError(f"Invalid GitHub URL: {url}")


def clone_repo(repo_url, dest_dir):
    """Clone a public GitHub repository.

    Args:
        repo_url (str): GitHub repository URL.
        dest_dir (str): Destination directory for cloning.

    Returns:
        str: Path to the cloned repository.

    Raises:
        RuntimeError: If git clone fails.
    """
    repo_path = parse_github_url(repo_url)
    clone_url = f"https://github.com/{repo_path}.git"

    print(Fore.CYAN + f"[*] Cloning {clone_url} ..." + Style.RESET_ALL)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, dest_dir],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr}")

    print(Fore.GREEN + f"[+] Cloned successfully to {dest_dir}" + Style.RESET_ALL)
    return dest_dir


def scan_path(path, rules, ignore_patterns):
    """Scan a directory for secrets.

    Args:
        path (str): Path to directory to scan.
        rules (dict): Rules dictionary with 'rules' key.
        ignore_patterns (set): Set of directory names to ignore.

    Returns:
        list: List of findings.
    """
    scanner = Scanner(rules, ignore_patterns)
    return scanner.scan(path)


def run_local_scan(path):
    """Convenience function for GUI: scan a local path and return findings.

    Args:
        path (str): Path to scan.

    Returns:
        list: Findings.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    rules = load_rules(rules_dir)
    ignore_patterns = load_ignore_patterns(rules_dir)
    return scan_path(path, rules, ignore_patterns)


def run_remote_scan(url, show_tree=False):
    """Convenience function for GUI: scan a remote GitHub repo.

    Args:
        url (str): GitHub repository URL.
        show_tree (bool): If True, capture and return the tree output as a string.

    Returns:
        tuple: (findings list, tree_output or None)
    """
    tmpdir = tempfile.mkdtemp(prefix="secretscan_")
    tree_output = None
    try:
        clone_repo(url, tmpdir)

        if show_tree:
            # Capture stdout from show_tree
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()

            ignore_patterns = load_ignore_patterns(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
            )
            from core.tree import show_tree as render_tree
            render_tree(tmpdir, ignore_patterns)

            tree_output = sys.stdout.getvalue()
            sys.stdout = old_stdout



        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_dir = os.path.join(base_dir, "rules")
        rules = load_rules(rules_dir)
        ignore_patterns = load_ignore_patterns(rules_dir)
        findings = scan_path(tmpdir, rules, ignore_patterns)
        return findings, tree_output
    finally:
        pass


def _print_report(findings, title="SecretScan Report", target=None, base_path=None):
    """Print findings to console in a formatted way.

    Args:
        findings (list): List of finding dictionaries.
        title (str): Title to display.
        target (str, optional): Target URL or path.
        base_path (str, optional): Base path to make file paths relative to.
    """
    print("=" * 50)
    print(title)
    if target:
        print(f" Target: {target}")
    print("=" * 50)

    if not findings:
        print("\n  [!] No secrets found.\n")
        return

    for finding in findings:
        severity_color = {
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.GREEN,
            "info": Fore.BLUE,
        }.get(finding['severity'].lower(), Fore.WHITE)
        print(f"{severity_color}[{finding['severity']}] {finding['rule']}")
        file_path = finding["file"]
        if base_path:
            file_path = os.path.relpath(file_path, base_path)
        print(f"  File : {Fore.RED}{file_path}")
        print(f"  Line : {finding['line']}")
        print(f"  Match: {finding['match']}")
        print()

    print(f"Secrets Found: {len(findings)}")


def _save_report(findings, output_file="report.json"):
    """Save findings to a JSON file.

    Args:
        findings (list): List of finding dictionaries.
        output_file (str): Output file path.
    """
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Saved: {output_file}")


def interactive_menu():
    """Run an interactive text-based menu for the scanner."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    rules = load_rules(rules_dir)
    ignore_patterns = load_ignore_patterns(rules_dir)

    while True:
        print(Fore.CYAN + BANNER)
        print(Fore.CYAN + "Select an option:" + Style.RESET_ALL)
        print(Fore.GREEN + "  1) Scan Local Directory" + Style.RESET_ALL)
        print(Fore.GREEN + "  2) Scan Remote GitHub" + Style.RESET_ALL)
        print(Fore.GREEN + "  3) Help" + Style.RESET_ALL)
        print(Fore.GREEN + "  4) Exit" + Style.RESET_ALL)
        choice = input(Fore.CYAN + "Enter choice [1-4]: " + Style.RESET_ALL).strip()

        if choice == "1":
            path = input(Fore.CYAN + "Enter path to scan (default .): " + Style.RESET_ALL).strip()
            if not path:
                path = "."
            print(Fore.CYAN + f"\nScanning: {path}" + Style.RESET_ALL)
            findings = scan_path(path, rules, ignore_patterns)
            _print_report(findings, title="SecretScan Report")
            _save_report(findings, output_file="report.json")
            input(Fore.CYAN + "\nPress Enter to return to menu..." + Style.RESET_ALL)

        elif choice == "2":
            url = input(Fore.CYAN + "Enter GitHub repository URL: " + Style.RESET_ALL).strip()
            if not url:
                print(Fore.RED + "No URL provided." + Style.RESET_ALL)
                continue
            show_tree_input = input(Fore.CYAN + "Show directory tree before scanning? (y/N): " + Style.RESET_ALL).strip().lower()
            show_tree_flag = show_tree_input == "y" or show_tree_input == "yes"
            tmpdir = tempfile.mkdtemp(prefix="secretscan_")
            try:
                clone_repo(url, tmpdir)

                # First, scan to get findings
                findings = scan_path(tmpdir, rules, ignore_patterns)

                if show_tree_flag:
                    print("\n" + "=" * 50)
                    print(" Repository Structure")
                    print("=" * 50)
                    # Get the set of relative file paths that have secrets
                    secret_files = set()
                    for f in findings:
                        rel_path = os.path.relpath(f["file"], tmpdir)
                        secret_files.add(rel_path)
                    show_tree(tmpdir, ignore_patterns, "", tmpdir, secret_files)
                    print()

                _print_report(
                    findings,
                    title="SecretScan Report (Remote)",
                    target=url,
                    base_path=tmpdir,
                )
                _save_report(findings, output_file="report.json")
            except Exception as exc:
                print(Fore.RED + f"[-] Error: {exc}" + Style.RESET_ALL)
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
            input(Fore.CYAN + "\nPress Enter to return to menu..." + Style.RESET_ALL)

        elif choice == "3":
            print(Fore.CYAN + "\nScanner Help" + Style.RESET_ALL)
            print(Fore.CYAN + "-------------------" + Style.RESET_ALL)
            print(Fore.GREEN + "Scan Local Directory: Scan a folder on your computer for secrets." + Style.RESET_ALL)
            print(Fore.GREEN + "Scan Remote GitHub:   Enter a GitHub repo URL (e.g., https://github.com/user/repo)." + Style.RESET_ALL)
            print(Fore.GREEN + "                      Optionally view the directory tree before scanning." + Style.RESET_ALL)
            print(Fore.GREEN + "Help:                 Show this help message." + Style.RESET_ALL)
            print(Fore.GREEN + "Exit:                 Quit the program." + Style.RESET_ALL)
            print(Fore.CYAN + "\nResults are displayed above and saved to report.json in the current folder.\n" + Style.RESET_ALL)
            input(Fore.CYAN + "Press Enter to return to menu..." + Style.RESET_ALL)

        elif choice == "4":
            print(Fore.CYAN + "Goodbye!" + Style.RESET_ALL)
            break

        else:
            print(Fore.RED + "Invalid choice, please try again." + Style.RESET_ALL + "\n")


def main():
    """Entry point for the secret scanner CLI."""
    parser = argparse.ArgumentParser(prog="secretscan")
    subparsers = parser.add_subparsers(dest="command")

    # Local scan
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")

    # Remote scan - GitHub URL
    remote_parser = subparsers.add_parser("remote")
    remote_parser.add_argument("url", help="GitHub repository URL (e.g., https://github.com/owner/repo)")
    remote_parser.add_argument(
        "--tree", action="store_true", help="Show directory structure (with secret files highlighted in red) after scanning"
    )

    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "rules")
    rules = load_rules(rules_dir)
    ignore_patterns = load_ignore_patterns(rules_dir)

    if args.command == "scan":
        findings = scan_path(args.path, rules, ignore_patterns)
        _print_report(findings, title="SecretScan Report")
        _save_report(findings, output_file="report.json")
    elif args.command == "remote":
        tmpdir = tempfile.mkdtemp(prefix="secretscan_")
        try:
            clone_repo(args.url, tmpdir)

            # First, scan to get findings
            findings = scan_path(tmpdir, rules, ignore_patterns)

            if args.tree:
                print("\n" + "=" * 50)
                print(" Repository Structure")
                print("=" * 50)
                secret_files = set()
                for f in findings:
                    rel_path = os.path.relpath(f["file"], tmpdir)
                    secret_files.add(rel_path)
                show_tree(tmpdir, ignore_patterns, "", tmpdir, secret_files)
                print()

            _print_report(
                findings,
                title="SecretScan Report (Remote)",
                target=args.url,
                base_path=tmpdir,
            )
            _save_report(findings, output_file="report.json")
        except Exception as exc:
            print(f"[-] Error: {exc}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()