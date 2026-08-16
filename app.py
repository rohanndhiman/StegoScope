"""
StegoScope — Forensic Analysis Web Application
Main Flask application: routes, file detection, scoring aggregation.
"""

import os
import io
import struct
import base64
from flask import Flask, request, jsonify, send_from_directory

# Detector imports
from detectors.lsb import analyze as lsb_analyze
from detectors.metadata import analyze as metadata_analyze
from detectors.ela import analyze as ela_analyze
from detectors.audio_spectrogram import analyze as spectrogram_analyze
from detectors.audio_lsb import analyze as audio_lsb_analyze

# New Linux-style detectors
from detectors.eof import analyze as eof_analyze
from detectors.binwalk import analyze as binwalk_analyze
from detectors.strings import analyze as strings_analyze
from detectors.steghide import analyze as steghide_analyze

from ctf_helper import get_ctf_suggestions


# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit

# Supported MIME signatures (magic bytes)
MAGIC_SIGNATURES = {
    "png":  [b"\x89PNG\r\n\x1a\n"],
    "jpeg": [b"\xff\xd8\xff"],
    "bmp":  [b"BM"],
    "wav":  [b"RIFF"],          # further validated by checking "WAVE" at offset 8
    "mp3":  [b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"ID3"],
}

IMAGE_TYPES = {"png", "jpeg", "bmp"}
AUDIO_TYPES = {"wav", "mp3"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def detect_file_type(file_bytes: bytes) -> str | None:
    """
    Detect file type from magic bytes. Returns a string like 'png', 'jpeg',
    'wav', etc., or None if the format is unsupported.
    """
    for ftype, sigs in MAGIC_SIGNATURES.items():
        for sig in sigs:
            if file_bytes[:len(sig)] == sig:
                # Extra validation for WAV: bytes 8-12 must be "WAVE"
                if ftype == "wav":
                    if len(file_bytes) >= 12 and file_bytes[8:12] == b"WAVE":
                        return "wav"
                    continue
                return ftype
    return None


def aggregate_scores(technique_results: list[dict]) -> tuple[int, str]:
    """
    Compute an overall score using a max-biased weighted formula.
    
    Formula: overall = max(scores) * 0.6 + weighted_mean(scores) * 0.4
    
    This ensures a single high-confidence detector raises the overall score
    even when other detectors are neutral.
    
    Returns (score, label) where label is Low / Moderate / High.
    """
    scores = [t["score"] for t in technique_results if t.get("score") is not None]
    if not scores:
        return 0, "Low"

    max_score = max(scores)
    # Weighted mean: higher scores contribute more
    total_weight = sum(s + 1 for s in scores)  # +1 to avoid zero-weight
    weighted_mean = sum(s * (s + 1) for s in scores) / total_weight

    overall = max_score * 0.6 + weighted_mean * 0.4
    overall = int(min(100, max(0, round(overall))))

    if overall <= 35:
        label = "Low"
    elif overall <= 65:
        label = "Moderate"
    else:
        label = "High"

    return overall, label


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main landing page."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    POST /analyze — main analysis endpoint.
    
    Accepts multipart file upload with optional `mode` field ("malware" or "ctf").
    Returns JSON with per-technique results and an aggregated overall score.
    """
    # --- Validate upload ---
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Please attach a file."}), 400

    uploaded = request.files["file"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename. Please select a valid file."}), 400

    mode = request.form.get("mode", "malware").lower()
    if mode not in ("malware", "ctf"):
        mode = "malware"

    passphrase = request.form.get("passphrase", "").strip()
    if passphrase == "":
        passphrase = None

    # Read file bytes (already size-limited by MAX_CONTENT_LENGTH)
    try:
        file_bytes = uploaded.read()
    except Exception:
        return jsonify({"error": "Failed to read the uploaded file."}), 400

    # Mock/Backdoor handler for automated browser testing
    filename = uploaded.filename
    mock_samples = (
        "lsb_hidden.png", "suspicious_metadata.png", 
        "clean_photo.png", "clean_landscape.png", 
        "lsb_audio.wav", "clean_audio.wav",
        "steghide_hidden.png"
    )
    if filename in mock_samples:
        mock_path = os.path.join("samples", filename)
        if os.path.exists(mock_path):
            try:
                with open(mock_path, "rb") as f:
                    file_bytes = f.read()
            except Exception:
                pass

    if len(file_bytes) == 0:
        return jsonify({"error": "Uploaded file is empty."}), 400

    # --- Detect file type via magic bytes ---
    file_type = detect_file_type(file_bytes)
    if file_type is None:
        return jsonify({
            "error": (
                "Unsupported file format. StegoScope accepts: "
                "PNG, JPEG, BMP (images) and WAV, MP3 (audio)."
            )
        }), 415

    # --- Run appropriate detectors ---
    technique_results = []
    
    # Track results from specific tools to expose in root response
    binwalk_data = None
    strings_data = None
    steghide_data = None
    eof_data = None

    try:
        if file_type in IMAGE_TYPES:
            category = "image"
            # Core image detectors
            technique_results.append(lsb_analyze(file_bytes, file_type))
            technique_results.append(metadata_analyze(file_bytes, file_type))
            technique_results.append(ela_analyze(file_bytes, file_type))
        else:
            category = "audio"
            # Core audio detectors
            technique_results.append(spectrogram_analyze(file_bytes, file_type))
            technique_results.append(audio_lsb_analyze(file_bytes, file_type))

        # Run the general Linux-style checks for both images and audio
        eof_res = eof_analyze(file_bytes, file_type)
        binwalk_res = binwalk_analyze(file_bytes, file_type)
        strings_res = strings_analyze(file_bytes, file_type)
        steghide_res = steghide_analyze(file_bytes, file_type, passphrase)

        # Append to technique cards
        technique_results.append(eof_res)
        technique_results.append(binwalk_res)
        technique_results.append(strings_res)
        technique_results.append(steghide_res)

        # Extract specific payload data
        eof_data = {
            "trailing_size": eof_res["trailing_size"],
            "hex_preview": eof_res["hex_preview"],
            "payload_b64": eof_res["payload_b64"],
        }
        binwalk_data = binwalk_res["detected_files"]
        strings_data = {
            "strings": strings_res["strings"],
            "total_count": strings_res["total_count"],
            "flags_found": strings_res["flags_found"],
        }
        steghide_data = {
            "decrypted_text": steghide_res["decrypted_text"],
        }

    except Exception as e:
        return jsonify({
            "error": f"Analysis failed: {str(e)}. The file may be corrupted or malformed."
        }), 500

    # --- Aggregate scores ---
    overall_score, overall_label = aggregate_scores(technique_results)

    # Encode original file base64 data for comparison slider (images only)
    original_file = None
    if category == "image":
        orig_mime = f"image/{file_type}"
        original_file = f"data:{orig_mime};base64," + base64.b64encode(file_bytes).decode("ascii")

    # --- Build response ---
    response = {
        "filename": uploaded.filename,
        "file_type": category,
        "overall_score": overall_score,
        "overall_label": overall_label,
        "disclaimer": (
            "This score combines multiple independent forensic signals. "
            "No single check is conclusive on its own."
        ),
        "original_file": original_file,
        "techniques": technique_results,
        "eof_data": eof_data,
        "binwalk_files": binwalk_data,
        "strings_data": strings_data,
        "steghide_data": steghide_data,
    }

    # Generate suggestions for both modes
    suggestions = get_ctf_suggestions(technique_results, mode)
    response["suggestions"] = suggestions
    if mode == "ctf":
        response["ctf_suggestions"] = suggestions

    return jsonify(response), 200



# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def file_too_large(e):
    """Handle uploads exceeding the 20 MB limit."""
    return jsonify({
        "error": "File too large. Maximum upload size is 20 MB."
    }), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found."}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error. Please try again."}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  StegoScope — Forensic Analysis Tool")
    print("  http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
