"""Shannon entropy calculator for memory region classification.

Critical thresholds for encrypted/compressed data:
  - Entropy > 7.5  → encrypted / compressed (NOT valid code)
  - Entropy 4.5–6.5 → likely x86 machine code
  - Entropy < 3.0  → likely padding / zero-filled
"""

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def sliding_entropy(data: bytes, window_size: int = 4096, step: int = 2048) -> list[tuple[int, float]]:
    results = []
    for offset in range(0, len(data) - window_size + 1, step):
        window = data[offset:offset + window_size]
        results.append((offset, shannon_entropy(window)))
    return results


def is_likely_encrypted(data: bytes, threshold: float = 7.0) -> bool:
    return shannon_entropy(data) >= threshold


def is_likely_code(data: bytes, min_entropy: float = 4.5, max_entropy: float = 6.5) -> bool:
    e = shannon_entropy(data)
    return min_entropy <= e <= max_entropy
