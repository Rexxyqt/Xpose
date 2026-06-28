import os
from colorama import Fore, Style

def show_tree(path, ignore_patterns, prefix="", root=None, secret_files=None):
    """Display folder tree structure.

    Args:
        path: Current directory path.
        ignore_patterns: Set of directory names to ignore.
        prefix: String to prepend to each line (for tree structure).
        root: Root directory of the tree (used to compute relative paths).
        secret_files: Set of relative file paths (from root) that contain secrets.
    """
    items = []
    try:
        items = sorted(os.listdir(path))
    except:
        return

    # Filter out ignored dirs
    items = [i for i in items if i not in ignore_patterns]

    for i, item in enumerate(items):
        is_last = (i == len(items) - 1)
        connector = "`-- " if is_last else "|-- "
        item_path = os.path.join(path, item)

        if os.path.isdir(item_path):
            print(f"{prefix}{connector}{item}/")
            extension = "    " if is_last else "|   "
            # Pass the same root and secret_files to recursive call
            show_tree(item_path, ignore_patterns, prefix + extension, root, secret_files)
        else:
            # If we have a root and secret_files, check if this file is in secret_files
            if root is not None and secret_files is not None:
                # Compute relative path from root to this file
                try:
                    rel_path = os.path.relpath(item_path, root)
                except ValueError:
                    # This should not happen, but just in case
                    rel_path = item
                if rel_path in secret_files:
                    # Print the file name in red
                    print(f"{prefix}{connector}{Fore.RED}{item}{Style.RESET_ALL}")
                else:
                    print(f"{prefix}{connector}{item}")
            else:
                print(f"{prefix}{connector}{item}")
