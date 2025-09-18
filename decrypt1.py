#!/usr/bin/env python3
# Hatagawa II — robust remote solver
# Requires: pip install z3-solver

import socket
import re
import time
import sys
import argparse
from typing import List, Tuple
from z3 import BitVec, BitVecVal, Solver, sat, Z3Exception

DEFAULT_HOST = "34.252.33.37"
DEFAULT_PORT = 31183

# Default collection size; 8–12 works well
DEFAULT_SAMPLES = 10
SOCKET_TIMEOUT = 5.0

CIPH_RE = re.compile(rb"BHFlagY\{([0-9a-fA-F]{32})\}")

def recv_all_until(sock: socket.socket, must_contain: bytes, overall_timeout: float = 5.0) -> bytes:
    sock.settimeout(SOCKET_TIMEOUT)
    end_time = time.time() + overall_timeout
    buf = b""
    while time.time() < end_time:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if must_contain in buf:
                return buf
        except socket.timeout:
            pass
    return buf

def get_ciphertexts(host: str, port: int, n: int) -> List[bytes]:
    cts: List[bytes] = []
    with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as s:
        # Read banner/menu to the initial prompt
        _ = recv_all_until(s, b">", overall_timeout=6.0)

        while len(cts) < n:
            # Send 's' (Stay)
            s.sendall(b"s\n")
            data = recv_all_until(s, b"BHFlagY{", overall_timeout=4.0)
            # It may print menu + river art again; search for last BHFlagY{...}
            matches = list(CIPH_RE.finditer(data))
            if not matches:
                # Try to receive a bit more once
                data2 = recv_all_until(s, b"BHFlagY{", overall_timeout=2.5)
                data += data2
                matches = list(CIPH_RE.finditer(data))
            if matches:
                ct_hex = matches[-1].group(1)  # last occurrence
                try:
                    ct = bytes.fromhex(ct_hex.decode())
                except ValueError:
                    print("[!] Non-hex payload encountered; continuing ...")
                    continue
                if len(ct) == 16:
                    cts.append(ct)
                    print(f"[+] Got ciphertext {len(cts)}: {ct_hex.decode()}")
            else:
                print("[!] Failed to parse ciphertext, retrying this sample...")
                # Optionally send another newline to refresh prompt
                try:
                    s.sendall(b"\n")
                except Exception:
                    pass

        # Politely walk away
        try:
            s.sendall(b"w\n")
        except Exception:
            pass
    return cts

def split64_be(b16: bytes) -> Tuple[int, int]:
    assert len(b16) == 16
    return (int.from_bytes(b16[:8], "big"), int.from_bytes(b16[8:], "big"))

def solve_with_z3(observations: List[Tuple[int, int]]) -> Tuple[int, int, int, int, int]:
    """
    observations[r] = (W1_r, W2_r) where:
      W1_r = S_{3r+1} XOR M1
      W2_r = S_{3r+2} XOR M2
    LCG: S_{k+1} = (a * S_k + c) mod 2^64
    Constraints:
      a % 8 == 5; c % 2 == 1
    Unknowns: a, c, S0 (seed), M1, M2.
    """
    n = len(observations)
    if n < 4:
        raise ValueError("Need at least 4 samples for a quick solve; collect more.")

    bv = lambda x: BitVecVal(x, 64)

    a  = BitVec("a", 64)
    c  = BitVec("c", 64)
    S0 = BitVec("S0", 64)
    M1 = BitVec("M1", 64)
    M2 = BitVec("M2", 64)

    # Build the state chain S_0 .. S_{3n+2}
    # Each menu call consumes 3 states; encryption uses states (3r+1) and (3r+2).
    S = [S0]
    for i in range(3*n + 2):
        S.append(a * S[i] + c)  # bit-vectors wrap mod 2^64 automatically

    sol = Solver()

    # Multiplier and increment constraints from challenge
    sol.add((a & bv(0x7)) == bv(5))   # a ≡ 5 (mod 8)
    sol.add((c & bv(0x1)) == bv(1))   # c odd

    # Observation constraints: ciphertext words are XOR of state and plaintext halves
    for r, (W1, W2) in enumerate(observations):
        idx1 = 3*r + 1
        idx2 = 3*r + 2
        sol.add(BitVecVal(W1, 64) == (S[idx1] ^ M1))
        sol.add(BitVecVal(W2, 64) == (S[idx2] ^ M2))

    print("[*] Solving constraints with Z3 ...")
    if sol.check() != sat:
        raise RuntimeError("Z3: UNSAT — try collecting more samples or re-run.")

    m = sol.model()
    a_val  = m.eval(a).as_long()
    c_val  = m.eval(c).as_long()
    s0_val = m.eval(S0).as_long()
    m1_val = m.eval(M1).as_long()
    m2_val = m.eval(M2).as_long()

    return a_val, c_val, s0_val, m1_val, m2_val

def verify_solution(obs: List[Tuple[int,int]], a: int, c: int, s0: int, m1: int, m2: int) -> bool:
    MOD = (1 << 64) - 1
    def nxt(x): return (a * x + c) & MOD
    # regenerate S_k and check all obs
    for r, (W1, W2) in enumerate(obs):
        # states per round: S_{3r+1}, S_{3r+2}, S_{3r+3}
        # compute S_{3r+1} from S0 iteratively
        # efficient: step forward cumulatively
        pass
    # Efficient regeneration:
    S = s0
    for r, (W1, W2) in enumerate(obs):
        S = nxt(S)             # S_{3r+1}
        W1_chk = S ^ m1
        S = nxt(S)             # S_{3r+2}
        W2_chk = S ^ m2
        S = nxt(S)             # S_{3r+3} (unused)
        if (W1_chk & ((1<<64)-1)) != W1 or (W2_chk & ((1<<64)-1)) != W2:
            return False
    return True

def main():
    ap = argparse.ArgumentParser(description="Hatagawa II remote solver (LCG + OTP reuse)")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--samples", type=int, default=DEFAULT_SAMPLES, help="ciphertexts to collect (>=4)")
    ap.add_argument("--retries", type=int, default=3, help="auto-retries if UNSAT/verification fails")
    args = ap.parse_args()

    attempts = 0
    while attempts <= args.retries:
        attempts += 1
        try:
            print(f"[*] Collecting {args.samples} ciphertexts from {args.host}:{args.port} (attempt {attempts}/{args.retries+1})")
            cts = get_ciphertexts(args.host, args.port, max(4, args.samples))
            if len(cts) < 4:
                print("[!] Not enough ciphertexts; retrying ...")
                continue

            obs = [split64_be(ct) for ct in cts]

            a_val, c_val, s0_val, m1_val, m2_val = solve_with_z3(obs)

            print(f"[+] Recovered LCG params:")
            print(f"    a  = 0x{a_val:016x}  (a % 8 = {a_val & 7})")
            print(f"    c  = 0x{c_val:016x}  (c % 2 = {c_val & 1})")
            print(f"    S0 = 0x{s0_val:016x}")
            print(f"[+] Recovered plaintext halves (big-endian 64-bit):")
            print(f"    M1 = 0x{m1_val:016x}")
            print(f"    M2 = 0x{m2_val:016x}")

            if not verify_solution(obs, a_val, c_val, s0_val, m1_val, m2_val):
                print("[!] Verification against collected samples FAILED — will retry.\n")
                continue

            # Build the 16-byte plaintext and print the actual flag
            m_bytes = m1_val.to_bytes(8, "big") + m2_val.to_bytes(8, "big")
            m_hex = m_bytes.hex()
            print("\n[FLAG lower]  BHFlagY{" + m_hex + "}")
            print("[FLAG UPPER]  BHFlagY{" + m_hex.upper() + "}")

            # optional: also show ASCII if printable (rare for this chall)
            if all(32 <= b < 127 for b in m_bytes):
                try:
                    m_ascii = m_bytes.decode("ascii")
                    print("[FLAG ascii ]  BHFlagY{" + m_ascii + "}")
                except UnicodeDecodeError:
                    pass
            return  # success; exit script

        except (Z3Exception, RuntimeError, ValueError) as e:
            print(f"[!] Solve error: {e}\n")
            # loop for retry
        except (socket.timeout, OSError) as e:
            print(f"[!] Network error: {e}\n")
            # loop for retry

    print("[x] Exhausted retries without a verified solution. Try increasing --samples or rerun.")

if __name__ == "__main__":
    main()
