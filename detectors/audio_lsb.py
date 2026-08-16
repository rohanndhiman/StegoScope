"""
StegoScope — Audio LSB Chi-Square Analysis

Same chi-square approach as the image LSB detector, applied to raw audio
sample values. Detects whether the least significant bits of audio samples
follow a random distribution (consistent with embedded data) or a natural
distribution.
"""

import io
import base64
import warnings
import numpy as np

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import librosa
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_SR = 22050
MAX_SAMPLES = 500_000  # Limit samples analyzed for performance


def _chi_square_audio_lsb(samples: np.ndarray) -> float:
    """
    Run chi-square test on audio sample LSBs.
    
    Returns suspicion score 0-1.
    """
    if np.issubdtype(samples.dtype, np.integer):
        int_samples = samples.astype(np.int16)
    else:
        int_samples = (samples * 32767).astype(np.int16)
    
    # Shift to unsigned range for pair analysis
    unsigned = int_samples.astype(np.int32) + 32768  # now 0-65535
    
    # We analyze the lower 8 bits (the LSB byte)
    lsb_byte = (unsigned & 0xFF).astype(np.int32)
    
    # Build histogram of LSB byte values (0-255)
    hist = np.bincount(lsb_byte, minlength=256).astype(np.float64)
    
    # Group into pairs: (0,1), (2,3), ..., (254,255)
    even_counts = hist[0::2]
    odd_counts = hist[1::2]
    
    expected = (even_counts + odd_counts) / 2.0
    mask = expected > 0
    
    if mask.sum() < 2:
        return 0.0
    
    chi2 = np.sum(((even_counts[mask] - expected[mask]) ** 2) / expected[mask])
    dof = mask.sum() - 1
    
    if dof <= 0:
        return 0.0
    
    # Z-score: negative = equalized = suspicious
    z = (chi2 - dof) / np.sqrt(2.0 * dof)
    suspicion = 1.0 / (1.0 + np.exp(z * 0.1))
    
    return float(np.clip(suspicion, 0, 1))


def _render_lsb_histogram(samples: np.ndarray) -> str:
    """
    Render a histogram of LSB bit values in the audio samples.
    Returns a base64-encoded PNG data URI.
    """
    if np.issubdtype(samples.dtype, np.integer):
        int_samples = samples.astype(np.int16)
    else:
        int_samples = (samples * 32767).astype(np.int16)
        
    lsb_bits = int_samples & 1
    
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), dpi=100)
    fig.patch.set_facecolor("#0d1117")
    
    colors = {"text": "#e6edf3", "grid": "#21262d", "accent1": "#58a6ff", "accent2": "#f78166"}
    
    # Plot 1: LSB bit distribution (0 vs 1)
    ax1 = axes[0]
    ax1.set_facecolor("#0d1117")
    zeros = np.sum(lsb_bits == 0)
    ones = np.sum(lsb_bits == 1)
    bars = ax1.bar(["Bit 0", "Bit 1"], [zeros, ones],
                   color=[colors["accent1"], colors["accent2"]], width=0.5,
                   edgecolor="#30363d")
    ax1.set_title("LSB Bit Distribution", color=colors["text"], fontsize=11)
    ax1.set_ylabel("Count", color=colors["text"])
    ax1.tick_params(colors=colors["text"])
    for spine in ax1.spines.values():
        spine.set_color("#30363d")
    ax1.grid(axis="y", color=colors["grid"], alpha=0.5)
    
    # Add count labels on bars
    for bar, count in zip(bars, [zeros, ones]):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{count:,}", ha="center", va="bottom",
                color=colors["text"], fontsize=9)
    
    # Plot 2: LSB byte value histogram (lower 8 bits)
    ax2 = axes[1]
    ax2.set_facecolor("#0d1117")
    unsigned = int_samples.astype(np.int32) + 32768
    lsb_byte = unsigned & 0xFF
    ax2.hist(lsb_byte, bins=64, color=colors["accent1"], edgecolor="#0d1117",
             alpha=0.8)
    ax2.set_title("LSB Byte Value Distribution", color=colors["text"], fontsize=11)
    ax2.set_xlabel("Byte Value (0-255)", color=colors["text"])
    ax2.set_ylabel("Count", color=colors["text"])
    ax2.tick_params(colors=colors["text"])
    for spine in ax2.spines.values():
        spine.set_color("#30363d")
    ax2.grid(axis="y", color=colors["grid"], alpha=0.5)
    
    fig.tight_layout(pad=2)
    
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Run LSB chi-square analysis on audio samples.
    
    Args:
        file_bytes: Raw bytes of the audio file.
        file_type: Detected file type string.
    
    Returns:
        Dict with name, score, explanation, and histogram visualization.
    """
    # Try reading lossless WAV exact int16 values using soundfile first to preserve LSBs
    try:
        import soundfile as sf
        y_int, sr = sf.read(io.BytesIO(file_bytes), dtype='int16')
        # Convert to mono if stereo
        if len(y_int.shape) > 1:
            y_int = y_int[:, 0]
    except Exception:
        # Fallback to librosa float loader
        try:
            y, sr = librosa.load(io.BytesIO(file_bytes), sr=TARGET_SR, mono=True)
            y_int = (y * 32767).astype(np.int16)
        except Exception as e:
            return {
                "name": "Audio LSB Analysis",
                "score": 0,
                "explanation": f"Could not decode audio for LSB analysis: {e}",
                "visualization": None,
            }
    
    if len(y_int) == 0:
        return {
            "name": "Audio LSB Analysis",
            "score": 0,
            "explanation": "Audio file appears to be empty.",
            "visualization": None,
        }
    
    # Limit sample count for performance
    if len(y_int) > MAX_SAMPLES:
        y_analysis = y_int[:MAX_SAMPLES]
    else:
        y_analysis = y_int
    
    # Run chi-square test
    suspicion = _chi_square_audio_lsb(y_analysis)
    score = int(round(suspicion * 100))
    score = min(100, max(0, score))
    
    # Generate visualization
    visualization = _render_lsb_histogram(y_analysis)
    
    # Build explanation
    total_samples = len(y_analysis)
    lsb_bits = y_analysis & 1
    ratio = np.mean(lsb_bits)  # should be ~0.5 for both natural and embedded
    
    if score >= 70:
        explanation = (
            f"Audio LSB distribution shows signs of non-random manipulation "
            f"across {total_samples:,} samples. The paired-value distribution "
            f"is consistent with embedded data (LSB 0/1 ratio: {ratio:.4f})."
        )
    elif score >= 40:
        explanation = (
            f"Some irregularity in audio LSB distribution detected across "
            f"{total_samples:,} samples. This may indicate partial or "
            f"low-capacity steganographic embedding."
        )
    else:
        explanation = (
            f"Audio LSB distribution appears natural across {total_samples:,} "
            f"samples. No significant signs of embedded data detected."
        )
    
    return {
        "name": "Audio LSB Analysis",
        "score": score,
        "explanation": explanation,
        "visualization": visualization,
    }

