"""Textbook affine interpolation. This file does not import SYMBIOTE.

It queries input 0 and each standard basis vector, then solves bias and
coefficients over GF(2). It has no hint, tie-break, or hypothesis bank.
"""

import json
import sys


def main() -> None:
    width = int(sys.argv[1])
    if not 1 <= width <= 8:
        raise SystemExit("width must be 1..8")
    queries = [0] + [1 << bit for bit in range(width)]
    answers = {}
    for query in queries:
        sys.stdout.write(json.dumps({"query": query}) + "\n")
        sys.stdout.flush()
        reply = json.loads(sys.stdin.readline())
        answers[query] = int(reply["y"])
    bias = answers[0]
    coefficients = 0
    for bit in range(width):
        if answers[1 << bit] ^ bias:
            coefficients |= 1 << bit
    sys.stdout.write(
        json.dumps(
            {
                "done": True,
                "coefficients": coefficients,
                "bias": bool(bias),
                "queries": len(queries),
            }
        )
        + "\n"
    )
    sys.stdout.flush()


if __name__ == "__main__":
    main()
