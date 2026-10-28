import math
from collections import Counter
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
def file_entropy(path, max_bytes=8 * 1024 * 1024) -> float:
    with open(path, "rb") as f:
        return shannon_entropy(f.read(max_bytes))
