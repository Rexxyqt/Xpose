import math
from collections import Counter

def entropy(s):
    if not s: return 0
    c = Counter(s)
    l = len(s)
    return -sum((n / l) * math.log2(n / l) for n in c.values())
