"""
StegoScope — Spectrogram Anomaly Detection (Audio)

Computes a spectrogram via librosa (STFT) and analyzes frequency bands
for anomalies that may indicate steganographic embedding:
- Unnatural flatness in high-frequency bands
- Structured patterns near the Nyquist frequency
- Sudden spectral changes inconsistent with natural audio

Uses matplotlib for spectrogram visualization (librosa's display depends on it).
"""

import io
import base64
import warnings
import numpy as np

# Suppress librosa/numba warnings for cleaner output
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import librosa
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_SR = 22050          # Resample to this rate for consistent analysis
N_FFT = 2048               # FFT window size
HOP_LENGTH = 512           # Hop length for STFT
HIGH_FREQ_PERCENTILE = 90  # Top percentage of frequency bands to analyze


def _analyze_spectral_flatness(S: np.ndarray, sr: int) -> tuple[float, list[dict]]:
    """
    Analyze spectral flatness across frequency bands to detect anomalies.
    
    Spectral flatness (Wiener entropy) measures how "noise-like" a signal is.
    Natural audio has varying flatness across bands; steganographic embedding
    in high-frequency bands creates unnaturally uniform flatness.
    
    Returns:
        suspicion: float 0-1 indicating how suspicious the spectrogram looks
        flagged_regions: list of dicts describing flagged frequency bands
    """
    freqs = librosa.fft_frequencies(sr=sr, n_fft=N_FFT)
    n_freq_bins = S.shape[0]
    
    # Divide spectrum into bands (roughly 500 Hz each)
    band_size = max(1, n_freq_bins // 20)
    bands = []
    for i in range(0, n_freq_bins - band_size + 1, band_size):
        band_data = S[i:i + band_size, :]
        # Spectral flatness per band (geometric mean / arithmetic mean)
        geo_mean = np.exp(np.mean(np.log(band_data + 1e-10), axis=0))
        arith_mean = np.mean(band_data, axis=0)
        flatness = np.mean(geo_mean / (arith_mean + 1e-10))
        
        freq_low = freqs[min(i, len(freqs) - 1)]
        freq_high = freqs[min(i + band_size, len(freqs) - 1)]
        energy = np.mean(band_data)
        
        bands.append({
            "index": i,
            "freq_low": float(freq_low),
            "freq_high": float(freq_high),
            "flatness": float(flatness),
            "energy": float(energy),
        })
    
    if len(bands) < 3:
        return 0.0, []
    
    # Focus on high-frequency bands (top 10%)
    cutoff_idx = int(len(bands) * HIGH_FREQ_PERCENTILE / 100)
    high_bands = bands[cutoff_idx:]
    low_mid_bands = bands[:cutoff_idx]
    
    # Compare flatness of high bands vs. lower bands
    high_flatness = np.mean([b["flatness"] for b in high_bands])
    low_mid_flatness = np.mean([b["flatness"] for b in low_mid_bands])
    
    flagged_regions = []
    suspicion = 0.0
    
    # Check 1: High-frequency bands with unusually high energy
    # (natural audio drops off in high frequencies)
    high_energy = np.mean([b["energy"] for b in high_bands])
    low_energy = np.mean([b["energy"] for b in low_mid_bands])
    
    if low_energy > 0 and high_energy / (low_energy + 1e-10) > 0.3:
        suspicion += 0.4
        flagged_regions.append({
            "description": f"High-frequency bands ({high_bands[0]['freq_low']:.0f}-{high_bands[-1]['freq_high']:.0f} Hz) "
                          f"have unusually high energy relative to lower bands",
            "freq_range": (high_bands[0]["freq_low"], high_bands[-1]["freq_high"]),
        })
    
    # Check 2: Structured patterns (low variance in flatness across time)
    for band in high_bands:
        band_slice = S[band["index"]:band["index"] + band_size, :]
        temporal_variance = np.var(np.mean(band_slice, axis=0))
        if temporal_variance < 0.001 and band["energy"] > 0.01:
            suspicion += 0.15
            flagged_regions.append({
                "description": f"Unnaturally uniform band at {band['freq_low']:.0f}-{band['freq_high']:.0f} Hz",
                "freq_range": (band["freq_low"], band["freq_high"]),
            })
    
    # Check 3: Flatness anomaly in high bands
    if high_flatness > 0.8 and low_mid_flatness < 0.5:
        suspicion += 0.3
        flagged_regions.append({
            "description": "High-frequency flatness significantly exceeds lower band flatness",
            "freq_range": (high_bands[0]["freq_low"], high_bands[-1]["freq_high"]),
        })
    
    suspicion = float(np.clip(suspicion, 0, 1))
    return suspicion, flagged_regions


def _render_spectrogram(y: np.ndarray, sr: int, flagged_regions: list[dict]) -> str:
    """
    Render the spectrogram as a PNG image with flagged regions highlighted.
    Returns a base64-encoded data URI.
    """
    fig, ax = plt.subplots(1, 1, figsize=(10, 4), dpi=100)
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")
    
    # Compute and display spectrogram
    S = librosa.amplitude_to_db(
        np.abs(librosa.stft(y, n_fft=N_FFT, hop_length=HOP_LENGTH)),
        ref=np.max,
    )
    
    img = librosa.display.specshow(
        S, sr=sr, hop_length=HOP_LENGTH, x_axis="time", y_axis="hz",
        ax=ax, cmap="magma",
    )
    
    # Highlight flagged regions with red overlay boxes
    for region in flagged_regions:
        if "freq_range" in region:
            freq_low, freq_high = region["freq_range"]
            duration = librosa.get_duration(y=y, sr=sr)
            rect = plt.Rectangle(
                (0, freq_low), duration, freq_high - freq_low,
                linewidth=2, edgecolor="#ff4444", facecolor="#ff444433",
                linestyle="--",
            )
            ax.add_patch(rect)
    
    ax.set_title("Spectrogram Analysis", color="#e6edf3", fontsize=12, pad=10)
    ax.tick_params(colors="#8b949e")
    ax.xaxis.label.set_color("#8b949e")
    ax.yaxis.label.set_color("#8b949e")
    for spine in ax.spines.values():
        spine.set_color("#30363d")
    
    fig.colorbar(img, ax=ax, format="%+2.0f dB").ax.tick_params(colors="#8b949e")
    fig.tight_layout()
    
    buf = io.BytesIO()
    fig.savefig(buf, format="png", facecolor=fig.get_facecolor(), edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Run spectrogram anomaly analysis on an audio file.
    
    Args:
        file_bytes: Raw bytes of the audio file.
        file_type: Detected file type string (e.g. "wav", "mp3").
    
    Returns:
        Dict with name, score, explanation, and spectrogram visualization.
    """
    try:
        # Load audio with librosa (handles WAV, MP3 via soundfile/audioread)
        y, sr = librosa.load(io.BytesIO(file_bytes), sr=TARGET_SR, mono=True)
    except Exception as e:
        return {
            "name": "Spectrogram Analysis",
            "score": 0,
            "explanation": f"Could not decode audio for spectrogram analysis: {e}",
            "visualization": None,
        }
    
    if len(y) == 0:
        return {
            "name": "Spectrogram Analysis",
            "score": 0,
            "explanation": "Audio file appears to be empty.",
            "visualization": None,
        }
    
    # Compute magnitude spectrogram for analysis
    S = np.abs(librosa.stft(y, n_fft=N_FFT, hop_length=HOP_LENGTH))
    
    # Analyze spectral flatness and detect anomalies
    suspicion, flagged_regions = _analyze_spectral_flatness(S, sr)
    
    score = int(round(suspicion * 100))
    score = min(100, max(0, score))
    
    # Generate visualization
    visualization = _render_spectrogram(y, sr, flagged_regions)
    
    # Build explanation
    if score >= 60:
        region_desc = "; ".join(r["description"] for r in flagged_regions[:3])
        explanation = (
            f"Spectrogram shows anomalous patterns in high-frequency bands. "
            f"Findings: {region_desc}. "
            f"This is consistent with data hidden in audio frequency bands."
        )
    elif score >= 30:
        explanation = (
            "Some spectral irregularities detected, but they may be within "
            "normal range for this type of audio content."
        )
    else:
        explanation = (
            "Spectrogram appears natural with no unusual patterns in "
            "frequency distribution or energy levels."
        )
    
    return {
        "name": "Spectrogram Analysis",
        "score": score,
        "explanation": explanation,
        "visualization": visualization,
    }
