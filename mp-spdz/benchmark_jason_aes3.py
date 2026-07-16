#!/usr/bin/env python3
"""
Companion benchmark for jason_aes3.mpc (the "partial" protocol: L boolean
checks + L AES evaluations, WITHOUT the +2 tag-verification AES calls for
H = E_K(0) and k0 = E_K(IV_0)). Run on the same hardware and with the same
methodology as benchmark_jason_aes_full.py, to isolate the cost of the
additional tag-binding checks from Section 4.4 from pure hardware
differences with the paper's originally reported table.

Usage:
    python3 benchmark_jason_aes3.py [trials]
"""

import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 else 5
BLOCK_RANGE = range(1, 8)

K = bytes(range(16))


def counter_block(i: int) -> int:
    return int.from_bytes(bytes([(i + 1) % 256] * 16), 'big')


def write_inputs(L: int):
    items = [counter_block(j) for j in range(1, L + 1)]
    with open(os.path.join(HERE, 'Programs', 'Public-Input', 'jason_aes3'), 'w') as f:
        f.write(f"{L}\n")
    with open(os.path.join(HERE, 'Player-Data', 'Input-P0-0'), 'w') as f:
        for x in items:
            f.write(f"{x}\n")
        f.write(f"{int.from_bytes(K, 'big')}\n")
    with open(os.path.join(HERE, 'Player-Data', 'Input-P1-0'), 'w') as f:
        for x in items:
            f.write(f"{x}\n")


def run_once(L: int) -> float:
    write_inputs(L)
    start = time.perf_counter()
    result = subprocess.run(
        ["Scripts/semi.sh", "jason_aes3"],
        cwd=HERE, capture_output=True, text=True, check=True,
    )
    elapsed = time.perf_counter() - start
    if "Final checking result: 1" not in result.stdout:
        raise RuntimeError(f"Unexpected MPC output for L={L}:\n{result.stdout}\n{result.stderr}")
    return elapsed


def main():
    print(f"{'L':>3} {'mean_ms':>10} {'stdev_ms':>10} {'min_ms':>8} {'max_ms':>8}  trials={TRIALS}")
    rows = []
    for L in BLOCK_RANGE:
        times_ms = []
        for _ in range(TRIALS):
            times_ms.append(run_once(L) * 1000)
        mean_ms = statistics.mean(times_ms)
        stdev_ms = statistics.stdev(times_ms) if len(times_ms) > 1 else 0.0
        rows.append((L, mean_ms, stdev_ms, min(times_ms), max(times_ms)))
        print(f"{L:>3} {mean_ms:>10.1f} {stdev_ms:>10.1f} {min(times_ms):>8.1f} {max(times_ms):>8.1f}")

    print("\nLaTeX table row (mean ms, rounded):")
    print(" & ".join(str(L) for L, *_ in rows))
    print(" & ".join(f"{mean_ms:.0f}" for _, mean_ms, *_ in rows))


if __name__ == '__main__':
    main()
