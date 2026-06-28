import subprocess
import tempfile
import shutil
import os

from remote.parser import parse_github_url
from rules.loader import load_rules, load_ignore_patterns


def clone_repo(repo_url, dest_dir):
    """Clone a public GitHub repo."""
    repo_path = parse_github_url(repo_url)
    clone_url = f"https://github.com/{repo_path}.git"

    print(f"[*] Cloning {clone_url} ...")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", clone_url, dest_dir],
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed: {result.stderr}")

    print(f"[+] Cloned successfully to {dest_dir}")
    return dest_dir


def remote_scan(url, rules=None, ignore_patterns=None, show_tree_flag=False):
    """Scan a remote GitHub repository.

    If `rules` or `ignore_patterns` are not provided, defaults from `Expose/rules` are loaded.

    Returns:
        (findings, tmpdir) where tmpdir is the cloned directory path.
    """
    tmpdir = tempfile.mkdtemp(prefix="expose_")
    try:
        # Load defaults if not provided
        if rules is None or ignore_patterns is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.normpath(os.path.join(base_dir, "..", "rules"))
            if rules is None:
                rules = load_rules(rules_dir)
            if ignore_patterns is None:
                ignore_patterns = load_ignore_patterns(rules_dir)

        clone_repo(url, tmpdir)

        if show_tree_flag:
            from core.tree import show_tree

            print("\n" + "=" * 50)
            print(" Repository Structure")
            print("=" * 50)
            show_tree(tmpdir, ignore_patterns)
            print()

        from core.scanner import Scanner

        scanner = Scanner(rules, ignore_patterns)
        res = scanner.scan(tmpdir)
        return res, tmpdir

    except Exception as e:
        print(f"[-] Error: {e}")
        return [], None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

