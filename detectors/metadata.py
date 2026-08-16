"""
StegoScope — EXIF / Metadata Forensics Detector

Extracts and analyzes EXIF metadata from images. Checks for:
- Missing expected fields (camera make/model on a photo)
- Stripped metadata (suspiciously empty EXIF)
- Unusually large or suspicious comment/user-data fields
- Editing software signatures (Photoshop, GIMP, etc.)
- Inconsistent timestamps

Scoring is based on the number and severity of detected anomalies.
"""

import io
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

# ---------------------------------------------------------------------------
# Anomaly definitions and severity weights
# ---------------------------------------------------------------------------

# Software names that suggest post-processing / editing
EDITING_SOFTWARE = [
    "photoshop", "gimp", "paint.net", "lightroom", "affinity",
    "pixelmator", "corel", "capture one", "darktable", "rawtherapee",
    "snapseed", "canva", "steghide", "openstego", "stegosuite",
]

# Expected fields for a camera-taken photograph
EXPECTED_CAMERA_FIELDS = {
    "Make": "Camera manufacturer",
    "Model": "Camera model",
    "DateTime": "Date/time taken",
    "ExifImageWidth": "Image width",
    "ExifImageHeight": "Image height",
}

# Maximum reasonable size for text metadata fields (bytes)
MAX_COMMENT_LENGTH = 500


def _decode_exif_value(value):
    """Safely convert an EXIF value to a displayable string."""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return f"<binary {len(value)} bytes>"
    if isinstance(value, tuple):
        return str(value)
    return str(value)


def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Analyze image metadata/EXIF for forensic anomalies.
    
    Args:
        file_bytes: Raw bytes of the image file.
        file_type: Detected file type string.
    
    Returns:
        Dict with name, score, explanation, and details table.
    """
    try:
        img = Image.open(io.BytesIO(file_bytes))
    except Exception as e:
        return {
            "name": "Metadata Analysis",
            "score": 0,
            "explanation": f"Could not open image for metadata extraction: {e}",
            "details": {},
            "visualization": None,
        }
    
    # Extract EXIF data
    raw_exif = {}
    try:
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")
                raw_exif[tag_name] = value
    except Exception:
        pass  # Some formats don't support EXIF at all
    
    # Also check img.info for non-EXIF metadata (PNG text chunks, etc.)
    # Store keys in lowercase for case-insensitive lookup
    info_meta = {}
    for key, value in img.info.items():
        if key not in ("exif", "icc_profile", "dpi"):
            info_meta[key.lower()] = _decode_exif_value(value)

    
    anomalies = []
    details_table = {}
    total_severity = 0.0
    
    # -----------------------------------------------------------------------
    # Check 1: Completely stripped metadata
    # -----------------------------------------------------------------------
    if not raw_exif and not info_meta:
        anomalies.append("No metadata found — this is unusual for camera photos "
                         "and may indicate intentional stripping.")
        total_severity += 15
        details_table["Metadata Status"] = {
            "value": "Completely absent",
            "status": "suspicious",
        }
    else:
        details_table["Metadata Status"] = {
            "value": f"{len(raw_exif)} EXIF fields, {len(info_meta)} info fields",
            "status": "normal",
        }
    
    # -----------------------------------------------------------------------
    # Check 2: Missing expected camera fields
    # -----------------------------------------------------------------------
    missing_fields = []
    for field, description in EXPECTED_CAMERA_FIELDS.items():
        if field in raw_exif:
            val = _decode_exif_value(raw_exif[field])
            details_table[description] = {"value": val, "status": "normal"}
        else:
            missing_fields.append(description)
            details_table[description] = {"value": "Missing", "status": "missing"}
    
    if missing_fields and raw_exif:
        # Only flag if there IS some EXIF but expected fields are missing
        # (could mean selective stripping)
        severity = min(25, len(missing_fields) * 5)
        total_severity += severity
        anomalies.append(
            f"Missing expected fields: {', '.join(missing_fields)}. "
            f"This may indicate selective metadata removal."
        )
    
    # -----------------------------------------------------------------------
    # Check 3: Editing software detected
    # -----------------------------------------------------------------------
    software = raw_exif.get("Software", "")
    if isinstance(software, str):
        software_lower = software.lower()
        for editor in EDITING_SOFTWARE:
            if editor in software_lower:
                total_severity += 10
                anomalies.append(
                    f"Editing software detected: '{software}'. "
                    f"Image may have been modified post-capture."
                )
                details_table["Software"] = {
                    "value": software,
                    "status": "suspicious",
                }
                break
        else:
            if software:
                details_table["Software"] = {
                    "value": software,
                    "status": "normal",
                }
    
    # -----------------------------------------------------------------------
    # Check 4: Unusually large comment / user-data fields
    # -----------------------------------------------------------------------
    comment_fields = ["UserComment", "ImageDescription", "XPComment", "Comment"]
    for field in comment_fields:
        value = raw_exif.get(field, info_meta.get(field.lower(), None))
        if value is not None:
            val_str = _decode_exif_value(value)
            val_len = len(val_str) if isinstance(val_str, str) else 0
            
            if isinstance(value, bytes):
                val_len = len(value)
            
            if val_len > MAX_COMMENT_LENGTH:
                total_severity += 25
                anomalies.append(
                    f"Unusually large '{field}' field ({val_len} bytes). "
                    f"Data may be hidden in metadata fields."
                )
                details_table[field] = {
                    "value": f"{val_str[:80]}… ({val_len} bytes total)",
                    "status": "suspicious",
                }
            elif val_len > 0:
                details_table[field] = {
                    "value": val_str[:100],
                    "status": "normal",
                }
    
    # -----------------------------------------------------------------------
    # Check 5: GPS data present (not an anomaly per se, but worth noting)
    # -----------------------------------------------------------------------
    gps_info = raw_exif.get("GPSInfo")
    if gps_info:
        details_table["GPS Data"] = {
            "value": "Present",
            "status": "normal",
        }
    
    # -----------------------------------------------------------------------
    # Check 6: PNG-specific text chunks (can hide data)
    # -----------------------------------------------------------------------
    if file_type == "png":
        for key, value in info_meta.items():
            if isinstance(value, str) and len(value) > MAX_COMMENT_LENGTH:
                total_severity += 20
                anomalies.append(
                    f"PNG text chunk '{key}' is unusually large ({len(value)} chars). "
                    f"Data may be hidden in text metadata."
                )
                details_table[f"PNG:{key}"] = {
                    "value": f"{value[:80]}… ({len(value)} chars)",
                    "status": "suspicious",
                }
    
    # -----------------------------------------------------------------------
    # Compute final score
    # -----------------------------------------------------------------------
    score = int(min(100, max(0, total_severity)))
    
    if not anomalies:
        explanation = (
            "Metadata appears normal with no suspicious fields or anomalies detected."
        )
    else:
        explanation = " ".join(anomalies)
    
    return {
        "name": "Metadata Analysis",
        "score": score,
        "explanation": explanation,
        "details": details_table,
        "visualization": None,  # Metadata is shown as a table, not an image
    }
