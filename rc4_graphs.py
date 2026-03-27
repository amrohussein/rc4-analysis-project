"""
Enhanced RC4 — Statistical Visualization
Generates comparison graphs between Original RC4 and Enhanced RC4
"""

import os
import math
import collections
import hashlib
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyBboxPatch

# ── Import algorithm from main file ────────────────────────────────────────
import sys
sys.path.insert(0, '/home/claude')
from rc4_modified_en import (
    rc4_original_ksa, rc4_original_prga,
    rc4_modified_ksa, rc4_modified_prga,
    calculate_entropy, chi_square_test, autocorrelation
)

# ── Style ───────────────────────────────────────────────────────────────────
DARK_BG    = '#0D1117'
PANEL_BG   = '#161B22'
BLUE       = '#2E75B6'
ORANGE     = '#E07B39'
GREEN      = '#3FB950'
RED        = '#F85149'
GRAY       = '#8B949E'
WHITE      = '#E6EDF3'
GOLD       = '#F0C040'

plt.rcParams.update({
    'figure.facecolor':  DARK_BG,
    'axes.facecolor':    PANEL_BG,
    'axes.edgecolor':    '#30363D',
    'axes.labelcolor':   WHITE,
    'xtick.color':       GRAY,
    'ytick.color':       GRAY,
    'text.color':        WHITE,
    'grid.color':        '#21262D',
    'grid.linewidth':    0.8,
    'font.family':       'monospace',
})

# ── Data Generation ─────────────────────────────────────────────────────────

def generate_keystreams(n_bytes=50000):
    key = b"AcademicResearchKey2024"
    iv  = os.urandom(16)
    derived = hashlib.sha256(key + iv).digest()

    S1 = rc4_original_ksa(key)
    orig = rc4_original_prga(S1, n_bytes)

    S2 = rc4_modified_ksa(derived)
    mod = rc4_modified_prga(S2, n_bytes, drop=512)

    return orig, mod


def first_byte_bias(n_samples=800, first_n=32):
    orig_avgs = [0.0] * first_n
    mod_avgs  = [0.0] * first_n
    expected  = 127.5

    for _ in range(n_samples):
        k = os.urandom(16)

        S = rc4_original_ksa(k)
        s = rc4_original_prga(S, first_n)
        for i in range(first_n):
            orig_avgs[i] += abs(s[i] - expected)

        dk = hashlib.sha256(k + os.urandom(16)).digest()
        S2 = rc4_modified_ksa(dk)
        s2 = rc4_modified_prga(S2, first_n, drop=512)
        for i in range(first_n):
            mod_avgs[i] += abs(s2[i] - expected)

    return (
        [v / n_samples for v in orig_avgs],
        [v / n_samples for v in mod_avgs],
    )


def entropy_over_position(stream, window=1000, step=500):
    positions, entropies = [], []
    for start in range(0, len(stream) - window, step):
        chunk = stream[start:start + window]
        positions.append(start + window // 2)
        entropies.append(calculate_entropy(chunk))
    return positions, entropies


def byte_frequency(stream):
    freq = collections.Counter(stream)
    return [freq.get(i, 0) for i in range(256)]


def performance_data():
    import time
    key  = b"AcademicResearchKey2024"
    data = os.urandom(50000)
    sizes   = [1_000, 5_000, 10_000, 25_000, 50_000]
    t_orig, t_mod = [], []

    for sz in sizes:
        chunk = data[:sz]
        reps  = max(1, 200_000 // sz)

        t0 = time.perf_counter()
        for _ in range(reps):
            S = rc4_original_ksa(key)
            rc4_original_prga(S, sz)
        t_orig.append((time.perf_counter() - t0) / reps * 1000)

        iv  = os.urandom(16)
        dk  = hashlib.sha256(key + iv).digest()
        t0  = time.perf_counter()
        for _ in range(reps):
            S2 = rc4_modified_ksa(dk)
            rc4_modified_prga(S2, sz, drop=512)
        t_mod.append((time.perf_counter() - t0) / reps * 1000)

    return sizes, t_orig, t_mod


# ── Plot helpers ─────────────────────────────────────────────────────────────

def styled_ax(ax, title, xlabel='', ylabel=''):
    ax.set_facecolor(PANEL_BG)
    for spine in ax.spines.values():
        spine.set_edgecolor('#30363D')
    ax.set_title(title, color=WHITE, fontsize=11, fontweight='bold', pad=10)
    if xlabel: ax.set_xlabel(xlabel, color=GRAY, fontsize=9)
    if ylabel: ax.set_ylabel(ylabel, color=GRAY, fontsize=9)
    ax.grid(True, alpha=0.4)
    ax.tick_params(colors=GRAY, labelsize=8)


# ── Main Figure ──────────────────────────────────────────────────────────────

def build_figure():
    print("  Generating keystreams ...")
    orig_stream, mod_stream = generate_keystreams(50000)

    print("  Analysing first-byte bias ...")
    bias_orig, bias_mod = first_byte_bias(800, 32)

    print("  Computing entropy over position ...")
    pos_o, ent_o = entropy_over_position(orig_stream)
    pos_m, ent_m = entropy_over_position(mod_stream)

    print("  Measuring byte frequency ...")
    freq_o = byte_frequency(orig_stream)
    freq_m = byte_frequency(mod_stream)

    print("  Benchmarking performance ...")
    sizes, t_orig, t_mod = performance_data()

    # ── Layout ──────────────────────────────────────────────────────────────
    fig = plt.figure(figsize=(18, 13), facecolor=DARK_BG)
    fig.suptitle(
        'Enhanced RC4  —  Statistical Analysis & Comparison',
        fontsize=17, fontweight='bold', color=WHITE, y=0.98
    )

    gs = gridspec.GridSpec(
        3, 3,
        figure=fig,
        hspace=0.52, wspace=0.38,
        left=0.06, right=0.97,
        top=0.93, bottom=0.07
    )

    # ── 1. Byte Frequency Distribution ──────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    x = np.arange(256)
    ax1.bar(x, freq_o, color=BLUE,   alpha=0.55, width=1.0, label='Original RC4')
    ax1.bar(x, freq_m, color=ORANGE, alpha=0.55, width=1.0, label='Enhanced RC4')
    ax1.axhline(50000 / 256, color=GREEN, lw=1.5, ls='--', label=f'Ideal ({50000//256})')
    styled_ax(ax1, '(1) Byte Frequency Distribution  (50 000 bytes)',
              'Byte Value (0–255)', 'Frequency')
    ax1.legend(fontsize=8, facecolor=PANEL_BG, labelcolor=WHITE, framealpha=0.8)

    # ── 2. Summary Metrics Card ──────────────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    ax2.set_facecolor(PANEL_BG)
    ax2.axis('off')
    styled_ax(ax2, '(2) Key Metrics at a Glance')

    metrics = [
        ('Shannon Entropy',
         f"{calculate_entropy(orig_stream):.4f}",
         f"{calculate_entropy(mod_stream):.4f}",
         '8.0000', True),
        ('Chi-Square χ²',
         f"{chi_square_test(orig_stream):.2f}",
         f"{chi_square_test(mod_stream):.2f}",
         '255.0', None),
        ('Autocorrelation',
         f"{autocorrelation(orig_stream):.5f}",
         f"{autocorrelation(mod_stream):.5f}",
         '0.0', None),
        ('Avg First-Byte Bias',
         f"{sum(bias_orig)/len(bias_orig):.3f}",
         f"{sum(bias_mod)/len(bias_mod):.3f}",
         '0.0', False),
    ]

    col_x  = [0.01, 0.38, 0.65, 0.88]
    headers = ['Metric', 'Original', 'Enhanced', 'Ideal']
    for cx, hdr in zip(col_x, headers):
        ax2.text(cx, 0.93, hdr, transform=ax2.transAxes,
                 color=GOLD, fontsize=8, fontweight='bold')

    row_ys = [0.77, 0.60, 0.43, 0.26]
    for (label, vo, vm, ideal, higher_better), ry in zip(metrics, row_ys):
        ax2.text(col_x[0], ry, label,  transform=ax2.transAxes, color=GRAY,  fontsize=7.5)
        ax2.text(col_x[1], ry, vo,     transform=ax2.transAxes, color=BLUE,  fontsize=7.5, fontweight='bold')
        if higher_better is True:
            c = GREEN if float(vm) > float(vo) else ORANGE
        elif higher_better is False:
            c = GREEN if float(vm) < float(vo) else ORANGE
        else:
            c = WHITE
        ax2.text(col_x[2], ry, vm,     transform=ax2.transAxes, color=c,     fontsize=7.5, fontweight='bold')
        ax2.text(col_x[3], ry, ideal,  transform=ax2.transAxes, color=GRAY,  fontsize=7.5)

    # ── 3. First-Byte Bias per Position ─────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :2])
    positions = list(range(1, 33))
    ax3.plot(positions, bias_orig, color=BLUE,   lw=2,   marker='o', ms=4, label='Original RC4')
    ax3.plot(positions, bias_mod,  color=ORANGE, lw=2,   marker='s', ms=4, label='Enhanced RC4')
    ax3.fill_between(positions, bias_orig, bias_mod,
                     where=[o > m for o, m in zip(bias_orig, bias_mod)],
                     alpha=0.15, color=GREEN, label='Improvement area')
    styled_ax(ax3, '(3) Initial-Byte Bias per Position  (avg deviation from 127.5)',
              'Keystream Byte Position', 'Mean |value − 127.5|')
    ax3.legend(fontsize=8, facecolor=PANEL_BG, labelcolor=WHITE, framealpha=0.8)

    # ── 4. Entropy Over Stream Position ─────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.plot(pos_o, ent_o, color=BLUE,   lw=1.8, label='Original RC4')
    ax4.plot(pos_m, ent_m, color=ORANGE, lw=1.8, label='Enhanced RC4', ls='--')
    ax4.axhline(8.0, color=GREEN, lw=1.2, ls=':', label='Max (8.0)')
    ax4.set_ylim(7.90, 8.02)
    styled_ax(ax4, '(4) Entropy by Stream Position\n(1 000-byte window)',
              'Stream Offset (bytes)', 'Shannon Entropy (bits)')
    ax4.legend(fontsize=7.5, facecolor=PANEL_BG, labelcolor=WHITE, framealpha=0.8)

    # ── 5. Performance Comparison ────────────────────────────────────────────
    ax5 = fig.add_subplot(gs[2, :2])
    kb = [s / 1000 for s in sizes]
    ax5.plot(kb, t_orig, color=BLUE,   lw=2, marker='o', ms=5, label='Original RC4')
    ax5.plot(kb, t_mod,  color=ORANGE, lw=2, marker='s', ms=5, label='Enhanced RC4')
    ax5.fill_between(kb, t_orig, t_mod, alpha=0.12, color=ORANGE, label='Overhead')
    styled_ax(ax5, '(5) Encryption Time vs Data Size',
              'Data Size (KB)', 'Time (ms)')
    ax5.legend(fontsize=8, facecolor=PANEL_BG, labelcolor=WHITE, framealpha=0.8)

    # ── 6. Overhead Bar ──────────────────────────────────────────────────────
    ax6 = fig.add_subplot(gs[2, 2])
    overhead = [(m - o) / o * 100 for o, m in zip(t_orig, t_mod)]
    bars = ax6.bar([f'{s//1000}K' for s in sizes], overhead,
                   color=[GREEN if v < 30 else ORANGE if v < 50 else RED for v in overhead],
                   width=0.55, edgecolor='#30363D')
    for bar, val in zip(bars, overhead):
        ax6.text(bar.get_x() + bar.get_width() / 2,
                 bar.get_height() + 0.5,
                 f'{val:.1f}%', ha='center', va='bottom',
                 color=WHITE, fontsize=8, fontweight='bold')
    ax6.axhline(30, color=GRAY, lw=1, ls='--', alpha=0.6)
    styled_ax(ax6, '(6) Overhead % per Data Size',
              'Data Size', 'Overhead (%)')

    # ── Footer ───────────────────────────────────────────────────────────────
    fig.text(0.5, 0.01,
             'Enhanced RC4  |  Double KSA + Drop-512 + Modified PRGA  |  Academic Research Project',
             ha='center', color=GRAY, fontsize=8)

    out = '/mnt/user-data/outputs/rc4_analysis_graphs.png'
    plt.savefig(out, dpi=160, bbox_inches='tight', facecolor=DARK_BG)
    plt.close()
    print(f"\n  Saved → {out}")
    return out


if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("  Enhanced RC4 — Graph Generator")
    print("=" * 55 + "\n")
    build_figure()
    print("  Done.\n")
