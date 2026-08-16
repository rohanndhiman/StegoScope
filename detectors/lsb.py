"""
StegoScope — LSB (Least Significant Bit) Chi-Square Analysis

Extracts the LSB plane from each color channel and runs a chi-square
goodness-of-fit test to determine whether the distribution is consistent
with random data (which suggests embedded steganographic content).

Key idea: in a natural image, adjacent pixel values (pairs like 0/1, 2/3,
4/5, …) tend to occur at unequal frequencies. LSB embedding equalizes
these pairs, and the chi-square test detects this equalization.
"""

import io
import base64
import numpy as np
from PIL import Image

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHANNEL_NAMES = ("Red", "Green", "Blue")


def _chi_square_lsb(channel_data: np.ndarray) -> float:
    """
    Run chi-square test on a single channel's pixel values.
    
    Groups pixel values into pairs (0,1), (2,3), (4,5), …, (254,255).
    Under normal conditions, members of each pair have different frequencies.
    LSB embedding makes them nearly equal, producing a high chi-square p-value.
    
    Returns a probability (0-1) that the LSB distribution is non-random
    (i.e., likely contains hidden data). Higher = more suspicious.
    """
    flat = channel_data.flatten().astype(np.int32)
    
    # Build histogram of all 256 values
    hist = np.bincount(flat, minlength=256).astype(np.float64)
    
    # Group into 128 pairs: (0,1), (2,3), ..., (254,255)
    even_counts = hist[0::2]   # values 0, 2, 4, …, 254
    odd_counts  = hist[1::2]   # values 1, 3, 5, …, 255
    
    # Expected: if LSB is random, each pair should be split evenly
    expected = (even_counts + odd_counts) / 2.0
    
    # Avoid division by zero — skip pairs where both counts are 0
    mask = expected > 0
    if mask.sum() == 0:
        return 0.0
    
    # Chi-square statistic
    chi2 = np.sum(((even_counts[mask] - expected[mask]) ** 2) / expected[mask])
    
    # Degrees of freedom = number of valid pairs - 1
    dof = mask.sum() - 1
    if dof <= 0:
        return 0.0
    
    # Approximate p-value using the normal approximation for large dof:
    # For large dof, (chi2 - dof) / sqrt(2*dof) ~ N(0,1)
    # We want: probability that the distribution looks RANDOM (embedded)
    # A very LOW chi-square (close to dof) means pairs are equalized → suspicious
    z = (chi2 - dof) / np.sqrt(2.0 * dof) if dof > 0 else 0
    
    # Convert z-score: negative z means chi2 < dof → equalized → suspicious
    # We want a 0-1 score where 1 = very suspicious (equalized)
    # Use a sigmoid-like mapping
    suspicion = 1.0 / (1.0 + np.exp(z * 0.4))  # scaled sigmoid
    
    return float(np.clip(suspicion, 0, 1))



def _render_lsb_plane(img_array: np.ndarray) -> str:
    """
    Generate a visual of the LSB bit-plane for each RGB channel,
    composited into one image. Bit=1 renders as white, bit=0 as black
    in each channel.
    
    Returns a base64-encoded PNG data URI.
    """
    h, w = img_array.shape[:2]
    
    if img_array.ndim == 2:
        # Grayscale: just show the single channel
        lsb = (img_array & 1) * 255
        vis = np.stack([lsb, lsb, lsb], axis=2).astype(np.uint8)
    else:
        # Extract LSB for each channel and amplify to 0/255
        channels = []
        for c in range(min(3, img_array.shape[2])):
            lsb = (img_array[:, :, c] & 1) * 255
            channels.append(lsb)
        # Pad to 3 channels if needed
        while len(channels) < 3:
            channels.append(np.zeros((h, w), dtype=np.uint8))
        vis = np.stack(channels, axis=2).astype(np.uint8)
    
    # Encode to base64 PNG
    pil_img = Image.fromarray(vis, "RGB")
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Run LSB chi-square analysis on an image.
    
    Args:
        file_bytes: Raw bytes of the image file.
        file_type: Detected file type string (e.g. "png", "jpeg").
    
    Returns:
        Dict with name, score, explanation, and visualization.
    """
    try:
        img = Image.open(io.BytesIO(file_bytes))
        img = img.convert("RGB")
        arr = np.array(img)
    except Exception as e:
        return {
            "name": "LSB Analysis",
            "score": 0,
            "explanation": f"Could not decode image for LSB analysis: {e}",
            "visualization": None,
        }
    
    # Run chi-square on each channel
    channel_scores = []
    for c in range(3):
        suspicion = _chi_square_lsb(arr[:, :, c])
        channel_scores.append(suspicion)
    
    # Overall score: take the maximum channel suspicion (if any single
    # channel carries hidden data, that's enough to flag it)
    max_suspicion = max(channel_scores)
    score = int(round(max_suspicion * 100))
    score = min(100, max(0, score))
    
    # Generate explanation
    channel_details = ", ".join(
        f"{CHANNEL_NAMES[i]}: {int(round(s * 100))}%"
        for i, s in enumerate(channel_scores)
    )
    
    if score >= 70:
        explanation = (
            f"Bit-plane shows non-random structure consistent with embedded data. "
            f"Channel scores — {channel_details}."
        )
    elif score >= 40:
        explanation = (
            f"Some irregularity detected in LSB distribution, possibly indicative "
            f"of partial embedding or low-capacity steganography. "
            f"Channel scores — {channel_details}."
        )
    else:
        explanation = (
            f"LSB distribution appears natural and consistent with an unmodified image. "
            f"Channel scores — {channel_details}."
        )
    
    # Generate bit-plane visualization
    visualization = _render_lsb_plane(arr)
    
    return {
        "name": "LSB Analysis",
        "score": score,
        "explanation": explanation,
        "visualization": visualization,
    }
