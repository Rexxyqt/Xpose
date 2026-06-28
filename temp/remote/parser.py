import re

def parse_github_url(url):
    """Parse GitHub URL to owner/repo format."""
    url = url.rstrip(".git").rstrip("/")
    
    patterns = [
        r"github\.com[:/]([^/]+)/([^/]+)",
        r"git@github\.com:([^/]+)/([^/]+)",
    ]
    
    for p in patterns:
        m = re.search(p, url)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    
    if re.match(r'^[\w.-]+/[\w.-]+$', url):
        return url
    
    raise ValueError(f"Invalid GitHub URL: {url}")
