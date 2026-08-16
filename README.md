# StegoScope — Forensic Steganography & Hidden Data Analysis

**StegoScope** is a forensic analysis web application that detects hidden data, tampering, and steganography in images and audio files. It combines five independent forensic detectors — LSB chi-square analysis, EXIF metadata forensics, Error Level Analysis, spectrogram anomaly detection, and audio LSB analysis — into a unified scoring engine with visual evidence for every finding. StegoScope operates in two modes: a general-purpose **Malware & File Check** mode for forensic verdicts, and a **CTF Analysis & Helper** mode that adds technique-specific hints for capture-the-flag challenges.

> **Disclaimer:** StegoScope is a forensic *assistant*, not an oracle. Every verdict is paired with a confidence score, a plain-language explanation, and visual evidence. No single signal is conclusive on its own.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate demo sample files
python generate_samples.py

# 3. Start the server
python app.py
```

Then open **http://localhost:5000** in your browser.

---

## Features

| Detector | File Types | What It Detects |
|---|---|---|
| **LSB Analysis** | PNG, JPEG, BMP | Hidden data in least significant bits (chi-square statistical test) |
| **Metadata Forensics** | PNG, JPEG, BMP | Stripped/stuffed EXIF fields, editing software traces, oversized comment fields |
| **Error Level Analysis** | PNG, JPEG, BMP | Image splicing, compositing, embedded overlays via recompression error differences |
| **Spectrogram Analysis** | WAV, MP3 | Anomalous frequency band patterns, unnatural high-frequency energy |
| **Audio LSB Analysis** | WAV, MP3 | Hidden data in audio sample least significant bits |

### Scoring
- Scores are aggregated using a **max-biased weighted formula** — a single high-confidence detector raises the overall score even if others are neutral
- Qualitative labels: **Low** (0-35), **Moderate** (36-65), **High** (66-100)
- Every result includes visual evidence (bit-plane images, heatmaps, spectrograms)

### CTF Helper
In CTF mode, detected signals are mapped to actionable suggestions with specific tool recommendations (zsteg, stegsolve, binwalk, Sonic Visualiser, etc.).

---

## Architecture

```
stegoscope/
├── app.py                      # Flask app, routes, scoring aggregation
├── detectors/
│   ├── lsb.py                  # Image LSB chi-square analysis
│   ├── metadata.py             # EXIF/metadata forensics
│   ├── ela.py                  # Error Level Analysis
│   ├── audio_spectrogram.py    # Spectrogram anomaly detection
│   └── audio_lsb.py            # Audio LSB chi-square analysis
├── ctf_helper.py               # Rules-based CTF suggestion mapper
├── static/
│   ├── index.html              # Single-page app (3 screens)
│   ├── style.css               # Dark-mode forensic dashboard CSS
│   └── app.js                  # Upload, rendering, animations
├── samples/                    # Generated demo files
├── generate_samples.py         # Demo sample creator
└── requirements.txt            # Pinned Python dependencies
```

---

## API

### `POST /analyze`

**Request:** Multipart form data with `file` (required) and `mode` (`"malware"` or `"ctf"`, optional, defaults to `"malware"`)

**Response:** JSON with overall score, per-technique results with visualizations, and (in CTF mode) suggested next steps.

---

## Tech Stack

- **Backend:** Python 3.11, Flask
- **Image Processing:** Pillow, NumPy
- **Audio Processing:** librosa, NumPy, matplotlib (spectrogram visualization only)
- **Frontend:** Vanilla HTML/CSS/JavaScript
- **No database, no external API calls, no ML model training** — fully offline, stateless analysis
