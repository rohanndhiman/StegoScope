"""
StegoScope — Error Level Analysis (ELA) Detector

Re-saves the image at a fixed JPEG quality, then computes the pixel-wise
difference between the original and the re-saved version. Regions with
significantly different error levels suggest editing, splicing, or
steganographic embedding.

Caveats:
- ELA is less reliable on lossless formats (PNG, BMP) because they don't
  have pre-existing JPEG compression artifacts to compare against.
- Already heavily compressed JPEGs may show uniform error, reducing ELA's
  discriminative power.
The detector handles these gracefully by capping confidence.
"""

import io
import base64
import numpy as np
from PIL import Image

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ELA_JPEG_QUALITY = 90       # Quality level for re-compression
ELA_AMPLIFICATION = 20      # Scale factor to amplify error differences
BLOCK_SIZE = 16             # Block size for variance analysis
PNG_CONFIDENCE_CAP = 30     # Max confidence score for PNG/BMP inputs


def _apply_heatmap(diff_array: np.ndarray) -> np.ndarray:
    """
    Convert a grayscale difference array (0-255) into an RGB heatmap.
    
    Colormap: dark blue → cyan → yellow → red for low → high error.
    This is a simple hand-rolled colormap to avoid matplotlib dependency.
    """
    # Normalize to 0-1
    norm = diff_array.astype(np.float64) / 255.0
    
    r = np.zeros_like(norm)
    g = np.zeros_like(norm)
    b = np.zeros_like(norm)
    
    # Dark blue (0.0) → Cyan (0.33) → Yellow (0.66) → Red (1.0)
    # Segment 1: 0.0 - 0.33 → dark blue to cyan
    mask1 = norm <= 0.33
    t1 = norm[mask1] / 0.33
    r[mask1] = 0
    g[mask1] = t1
    b[mask1] = 0.5 + 0.5 * t1
    
    # Segment 2: 0.33 - 0.66 → cyan to yellow
    mask2 = (norm > 0.33) & (norm <= 0.66)
    t2 = (norm[mask2] - 0.33) / 0.33
    r[mask2] = t2
    g[mask2] = 1.0
    b[mask2] = 1.0 - t2
    
    # Segment 3: 0.66 - 1.0 → yellow to red
    mask3 = norm > 0.66
    t3 = (norm[mask3] - 0.66) / 0.34
    r[mask3] = 1.0
    g[mask3] = 1.0 - t3
    b[mask3] = 0
    
    heatmap = np.stack([
        (r * 255).astype(np.uint8),
        (g * 255).astype(np.uint8),
        (b * 255).astype(np.uint8),
    ], axis=2)
    
    return heatmap


def _compute_block_variance(diff_gray: np.ndarray) -> float:
    """
    Compute the variance of error levels across non-overlapping blocks.
    
    High inter-block variance means some regions have very different
    compression error than others → suspicious.
    
    Returns a normalized suspicion score (0-1).
    """
    h, w = diff_gray.shape
    block_h = h // BLOCK_SIZE
    block_w = w // BLOCK_SIZE
    
    if block_h < 2 or block_w < 2:
        return 0.0
    
    # Compute mean error per block
    block_means = []
    for by in range(block_h):
        for bx in range(block_w):
            block = diff_gray[
                by * BLOCK_SIZE : (by + 1) * BLOCK_SIZE,
                bx * BLOCK_SIZE : (bx + 1) * BLOCK_SIZE,
            ]
            block_means.append(np.mean(block))
    
    block_means = np.array(block_means)
    
    # Compute coefficient of variation (normalized std dev)
    mean_val = np.mean(block_means)
    if mean_val < 1.0:
        return 0.0
    
    cv = np.std(block_means) / mean_val
    
    # Map CV to suspicion score (empirical thresholds)
    # CV > 0.8 is quite suspicious, CV < 0.2 is normal
    suspicion = np.clip((cv - 0.2) / 0.6, 0, 1)
    return float(suspicion)


def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Run Error Level Analysis on an image.
    
    Args:
        file_bytes: Raw bytes of the image file.
        file_type: Detected file type string.
    
    Returns:
        Dict with name, score, explanation, and heatmap visualization.
    """
    is_lossless = file_type in ("png", "bmp")
    
    try:
        original = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        # Resize massively large images to avoid Vercel timeouts (max 1200px)
        max_dim = 1200
        if original.width > max_dim or original.height > max_dim:
            original.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
    except Exception as e:
        return {
            "name": "Error Level Analysis",
            "score": 0,
            "explanation": f"Could not decode image for ELA: {e}",
            "visualization": None,
        }
    
    orig_array = np.array(original, dtype=np.float64)
    
    # Re-save at fixed JPEG quality
    buf = io.BytesIO()
    original.save(buf, format="JPEG", quality=ELA_JPEG_QUALITY)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")
    resaved_array = np.array(resaved, dtype=np.float64)
    
    # Compute absolute difference and amplify
    diff = np.abs(orig_array - resaved_array)
    diff_amplified = np.clip(diff * ELA_AMPLIFICATION, 0, 255).astype(np.uint8)
    
    # Grayscale version for analysis (max across channels)
    diff_gray = np.max(diff_amplified, axis=2)
    
    # Compute block variance score
    suspicion = _compute_block_variance(diff_gray)
    
    # Also consider overall error level (very low or very high is informative)
    mean_error = np.mean(diff_gray)
    if mean_error > 200:
        # Extremely high error everywhere — likely comparing very different
        # compression states (e.g., first JPEG compression of a raw)
        suspicion *= 0.5  # reduce confidence, it's noisy
    
    score = int(round(suspicion * 100))
    
    # Cap score for lossless formats
    if is_lossless:
        score = min(score, PNG_CONFIDENCE_CAP)
    
    score = min(100, max(0, score))
    
    # Generate heatmap visualization
    heatmap_rgb = _apply_heatmap(diff_gray)
    heatmap_img = Image.fromarray(heatmap_rgb, "RGB")
    heatmap_buf = io.BytesIO()
    heatmap_img.save(heatmap_buf, format="PNG")
    heatmap_b64 = base64.b64encode(heatmap_buf.getvalue()).decode("ascii")
    visualization = f"data:image/png;base64,{heatmap_b64}"
    
    # Build explanation
    if is_lossless:
        format_note = (
            " Note: ELA is less reliable on lossless formats like "
            f"{file_type.upper()} — confidence is capped accordingly."
        )
    else:
        format_note = ""
    
    if score >= 60:
        explanation = (
            "Significant variation in compression error levels detected. "
            "Regions with mismatched error suggest editing, splicing, or "
            "an embedded overlay." + format_note
        )
    elif score >= 30:
        explanation = (
            "Some variation in compression error levels. This could indicate "
            "minor modifications, though it may also be normal for certain "
            "image types." + format_note
        )
    else:
        explanation = (
            "Compression error levels appear uniform across the image, "
            "consistent with an unmodified file." + format_note
        )
    
    return {
        "name": "Error Level Analysis",
        "score": score,
        "explanation": explanation,
        "visualization": visualization,
    }
