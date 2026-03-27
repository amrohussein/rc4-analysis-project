"""
Enhanced RC4 Stream Cipher - Academic Research Project
Modifications: Drop-N + Double KSA + Modified PRGA
"""

import os
import math
import time
import random
import collections
import hashlib


# ============================================================
# 1. Original RC4
# ============================================================

def rc4_original_ksa(key: bytes) -> list:
    """Key Scheduling Algorithm (original)"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_original_prga(S: list, length: int) -> bytes:
    """Pseudo-Random Generation Algorithm (original)"""
    i = j = 0
    output = []
    S = S[:]
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        output.append(S[(S[i] + S[j]) % 256])
    return bytes(output)


def rc4_original(key: bytes, data: bytes) -> bytes:
    """Full original RC4 encryption/decryption"""
    S = rc4_original_ksa(key)
    keystream = rc4_original_prga(S, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))


# ============================================================
# 2. Enhanced RC4
# ============================================================

def rc4_modified_ksa(key: bytes) -> list:
    """
    Double KSA:
    - Pass 1: standard KSA
    - Pass 2: additional shuffle with a different index pattern
              to increase state diffusion
    """
    S = list(range(256))
    j = 0

    # Pass 1 - standard KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Pass 2 - secondary shuffle with different index pattern
    j = 0
    for i in range(256):
        j = (j + S[i] + key[(i * 3 + 7) % len(key)] + i) % 256
        S[i], S[j] = S[j], S[i]

    return S


def rc4_modified_prga(S: list, length: int, drop: int = 512) -> bytes:
    """
    Modified PRGA with Drop-N:
    - Discards the first `drop` output bytes (Drop-N)
    - Introduces a third variable k to increase output function complexity
    """
    i = j = k = 0
    S = S[:]

    # Drop-N: discard the first `drop` bytes
    for _ in range(drop):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        # k tracks additional state even during the drop phase
        k = (k + S[(i + j) % 256]) % 256

    # Modified PRGA with three state variables
    output = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        k = (k + S[(i + j) % 256]) % 256
        S[i], S[j] = S[j], S[i]
        # Output function depends on i, j, and k
        out_byte = S[(S[i] + S[j] + S[k]) % 256]
        output.append(out_byte)

    return bytes(output)


def rc4_modified(key: bytes, data: bytes, drop: int = 512) -> bytes:
    """Full enhanced RC4 encryption with secure IV derivation"""
    # Generate a fresh IV for every encryption call
    iv = os.urandom(16)
    derived_key = hashlib.sha256(key + iv).digest()

    S = rc4_modified_ksa(derived_key)
    keystream = rc4_modified_prga(S, len(data), drop)
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))

    # Prepend IV to ciphertext (IV is public, not secret)
    return iv + ciphertext


def rc4_modified_decrypt(key: bytes, data: bytes, drop: int = 512) -> bytes:
    """Enhanced RC4 decryption"""
    iv = data[:16]
    ciphertext = data[16:]
    derived_key = hashlib.sha256(key + iv).digest()

    S = rc4_modified_ksa(derived_key)
    keystream = rc4_modified_prga(S, len(ciphertext), drop)
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# ============================================================
# 3. Statistical Analysis
# ============================================================

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte)"""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def chi_square_test(data: bytes) -> float:
    """Chi-square test for uniformity of byte distribution"""
    freq = collections.Counter(data)
    total = len(data)
    expected = total / 256
    chi_sq = sum((freq.get(i, 0) - expected) ** 2 / expected for i in range(256))
    return chi_sq


def autocorrelation(data: bytes, lag: int = 1) -> float:
    """Compute autocorrelation at a given lag"""
    n = len(data)
    if n <= lag:
        return 0.0
    mean = sum(data) / n
    variance = sum((x - mean) ** 2 for x in data) / n
    if variance == 0:
        return 0.0
    cov = sum((data[i] - mean) * (data[i + lag] - mean) for i in range(n - lag)) / (n - lag)
    return cov / variance


def byte_distribution_uniformity(data: bytes) -> float:
    """
    Measure distribution uniformity.
    Returns a value in [0, 1] — closer to 1 means more uniform.
    """
    freq = collections.Counter(data)
    max_freq = max(freq.values())
    min_freq = min(freq.get(i, 0) for i in range(256))
    expected = len(data) / 256
    uniformity = 1 - (max_freq - min_freq) / (2 * expected)
    return max(0.0, min(1.0, uniformity))


def runs_test(data: bytes) -> dict:
    """Runs test for randomness (bit-level)"""
    bits = []
    for byte in data:
        for bit in range(8):
            bits.append((byte >> bit) & 1)

    n = len(bits)
    n1 = sum(bits)
    n0 = n - n1

    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1

    expected_runs = ((2 * n0 * n1) / n) + 1
    variance_runs = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n ** 2 * (n - 1)) if n > 1 else 1

    return {
        "runs": runs,
        "expected_runs": round(expected_runs, 2),
        "deviation": round(abs(runs - expected_runs), 2)
    }


def analyze_first_bytes_bias(key: bytes, n_samples: int = 1000, first_n: int = 16) -> dict:
    """
    Analyse initial-byte bias.
    Measures the average deviation from the expected mean (127.5)
    in the first N keystream bytes for both original and enhanced RC4.
    """
    original_first = [0] * first_n
    modified_first  = [0] * first_n

    for _ in range(n_samples):
        test_key = os.urandom(16)

        # Original RC4 - first N bytes directly
        S = rc4_original_ksa(test_key)
        stream = rc4_original_prga(S, first_n)
        for i in range(first_n):
            original_first[i] += stream[i]

        # Enhanced RC4 - bytes after the Drop phase
        derived = hashlib.sha256(test_key + os.urandom(16)).digest()
        S2 = rc4_modified_ksa(derived)
        stream2 = rc4_modified_prga(S2, first_n, drop=512)
        for i in range(first_n):
            modified_first[i] += stream2[i]

    expected = 127.5
    orig_bias = sum(abs(v / n_samples - expected) for v in original_first) / first_n
    mod_bias  = sum(abs(v / n_samples - expected) for v in modified_first)  / first_n

    return {
        "original_bias": round(orig_bias, 4),
        "modified_bias": round(mod_bias, 4),
        "improvement_percent": round((1 - mod_bias / orig_bias) * 100, 2) if orig_bias > 0 else 0
    }


# ============================================================
# 4. Full Comparison
# ============================================================

def run_comparison(data_size: int = 10000) -> dict:
    """Run a full statistical comparison between original and enhanced RC4"""

    key = b"AcademicResearchKey2024"
    plaintext = os.urandom(data_size)

    print(f"\n{'='*60}")
    print(f"  Running statistical comparison  (data size: {data_size} bytes)")
    print(f"{'='*60}\n")

    # --- Original RC4 ---
    t0 = time.perf_counter()
    S_orig      = rc4_original_ksa(key)
    ks_orig     = rc4_original_prga(S_orig, data_size)
    cipher_orig = bytes(a ^ b for a, b in zip(plaintext, ks_orig))
    time_orig   = (time.perf_counter() - t0) * 1000

    # --- Enhanced RC4 ---
    t0 = time.perf_counter()
    cipher_mod = rc4_modified(key, plaintext)
    time_mod   = (time.perf_counter() - t0) * 1000

    # --- Statistical tests ---
    print("  [1/4] Computing Shannon entropy ...")
    entropy_orig = calculate_entropy(cipher_orig)
    entropy_mod  = calculate_entropy(cipher_mod[16:])   # skip IV prefix

    print("  [2/4] Running chi-square test ...")
    chi_orig = chi_square_test(cipher_orig)
    chi_mod  = chi_square_test(cipher_mod[16:])

    print("  [3/4] Computing autocorrelation ...")
    ac_orig = autocorrelation(cipher_orig)
    ac_mod  = autocorrelation(cipher_mod[16:])

    print("  [4/4] Analysing initial-byte bias ...")
    bias_analysis = analyze_first_bytes_bias(key)

    # Verify round-trip correctness
    decrypted = rc4_modified_decrypt(key, cipher_mod)
    correct   = decrypted == plaintext

    print(f"\n  Decryption verification: {'PASSED' if correct else 'FAILED!'}\n")

    return {
        "data_size": data_size,
        "correctness": correct,
        "entropy": {
            "original": round(entropy_orig, 6),
            "modified": round(entropy_mod, 6),
            "max_possible": 8.0
        },
        "chi_square": {
            "original": round(chi_orig, 4),
            "modified": round(chi_mod, 4),
            "ideal": 255.0
        },
        "autocorrelation": {
            "original": round(ac_orig, 6),
            "modified": round(ac_mod, 6),
            "ideal": 0.0
        },
        "bias_analysis": bias_analysis,
        "performance_ms": {
            "original": round(time_orig, 4),
            "modified": round(time_mod, 4),
            "overhead_percent": round((time_mod - time_orig) / time_orig * 100, 2)
        }
    }


def print_results(results: dict):
    """Print comparison results in a structured format"""

    print(f"\n{'='*60}")
    print("           Statistical Comparison Results")
    print(f"{'='*60}\n")

    print(f"  [Entropy]  higher is better  |  max = 8.0 bits/byte")
    print(f"     Original RC4 : {results['entropy']['original']:.6f}")
    print(f"     Enhanced RC4 : {results['entropy']['modified']:.6f}")

    print(f"\n  [Chi-Square]  closer to 255 is better")
    print(f"     Original RC4 : {results['chi_square']['original']:.4f}")
    print(f"     Enhanced RC4 : {results['chi_square']['modified']:.4f}")

    print(f"\n  [Autocorrelation]  closer to 0 is better")
    print(f"     Original RC4 : {results['autocorrelation']['original']:.6f}")
    print(f"     Enhanced RC4 : {results['autocorrelation']['modified']:.6f}")

    b = results['bias_analysis']
    print(f"\n  [Initial-Byte Bias]  lower is better")
    print(f"     Original RC4 : {b['original_bias']:.4f}")
    print(f"     Enhanced RC4 : {b['modified_bias']:.4f}")
    print(f"     Improvement  : {b['improvement_percent']:.2f}%")

    p = results['performance_ms']
    print(f"\n  [Performance]")
    print(f"     Original RC4 : {p['original']:.4f} ms")
    print(f"     Enhanced RC4 : {p['modified']:.4f} ms")
    print(f"     Overhead     : {p['overhead_percent']:.2f}%")

    print(f"\n  Decryption correctness: {'PASSED' if results['correctness'] else 'FAILED'}")
    print(f"\n{'='*60}\n")

    return results


# ============================================================
# 5. Entry Point
# ============================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("   Enhanced RC4 -- Statistical Comparison")
    print("   Modifications: Double KSA + Drop-512 + Modified PRGA")
    print("=" * 60)

    # Quick sanity check
    key = b"TestKey"
    msg = b"Hello RC4 Modified!"
    enc = rc4_modified(key, msg)
    dec = rc4_modified_decrypt(key, enc)
    assert dec == msg, "Encryption/decryption round-trip failed!"
    print("\n  Initial test: PASSED\n")

    # Full statistical comparison
    results = run_comparison(data_size=50000)
    print_results(results)
