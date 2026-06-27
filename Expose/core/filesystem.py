import os

def walk_directory(path, ignore_patterns):
    for root, dirs, files in os.walk(path):
        # Modify dirs in-place to ignore specified patterns
        dirs[:] = [d for d in dirs if d not in ignore_patterns]
        yield root, dirs, files
