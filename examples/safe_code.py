"""Example: Safe code that should pass sandbox audit.

Normal Python code that doesn't attempt sandbox escapes.
"""

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Point:
    x: float
    y: float

    def distance(self, other: "Point") -> float:
        return math.sqrt((self.x - other.x) ** 2 + (self.y - other.y) ** 2)


def fibonacci(n: int) -> list[int]:
    """Generate fibonacci sequence."""
    if n <= 0:
        return []
    if n == 1:
        return [0]
    seq = [0, 1]
    for _ in range(2, n):
        seq.append(seq[-1] + seq[-2])
    return seq


def parse_data(text: str) -> dict:
    """Parse JSON data safely."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def word_count(text: str) -> dict[str, int]:
    """Count word frequencies."""
    counts: dict[str, int] = defaultdict(int)
    for word in re.findall(r'\b\w+\b', text.lower()):
        counts[word] += 1
    return dict(counts)


def matrix_multiply(a: list[list[float]], b: list[list[float]]) -> list[list[float]]:
    """Simple matrix multiplication."""
    rows_a, cols_a = len(a), len(a[0])
    rows_b, cols_b = len(b), len(b[0])
    if cols_a != rows_b:
        raise ValueError("Incompatible matrix dimensions")

    result = [[0.0] * cols_b for _ in range(rows_a)]
    for i in range(rows_a):
        for j in range(cols_b):
            for k in range(cols_a):
                result[i][j] += a[i][k] * b[k][j]
    return result


if __name__ == "__main__":
    p1 = Point(0, 0)
    p2 = Point(3, 4)
    print(f"Distance: {p1.distance(p2)}")
    print(f"Fibonacci(10): {fibonacci(10)}")
    print(f"Word count: {word_count('hello world hello')}")
