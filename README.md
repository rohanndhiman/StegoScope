<div align="center">
  <h1>🔍 StegoScope</h1>
  <p><strong>Advanced Forensic Steganography & Hidden Data Analysis Suite</strong></p>

  <p>
    <a href="https://github.com/rohanndhiman/StegoScope/stargazers"><img src="https://img.shields.io/github/stars/rohanndhiman/StegoScope?style=for-the-badge&color=00ff00" alt="Stars Badge"/></a>
    <a href="https://github.com/rohanndhiman/StegoScope/network/members"><img src="https://img.shields.io/github/forks/rohanndhiman/StegoScope?style=for-the-badge&color=00ff00" alt="Forks Badge"/></a>
    <a href="https://github.com/rohanndhiman/StegoScope/issues"><img src="https://img.shields.io/github/issues/rohanndhiman/StegoScope?style=for-the-badge&color=ff0000" alt="Issues Badge"/></a>
    <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Badge">
    <img src="https://img.shields.io/badge/Flask-Web_App-black?style=for-the-badge&logo=flask&logoColor=white" alt="Flask Badge">
    <a href="https://stegoscope.vercel.app/"><img src="https://img.shields.io/badge/Live_Demo-Vercel-black?style=for-the-badge&logo=vercel&logoColor=white" alt="Live on Vercel"></a>
  </p>
</div>

<br/>

**StegoScope** is a comprehensive, pure-Python forensic analysis web application designed to detect hidden data, tampering, and steganography in images and audio files. It aggregates five distinct forensic detection engines into a unified, scoring-based framework, providing visual evidence and context-aware hints for both malware analysts and CTF players.

> **⚠️ Disclaimer:** StegoScope is a forensic *assistant*, not an oracle. Every verdict is paired with a confidence score, a plain-language explanation, and visual evidence. No single signal is conclusive on its own.

---

## ✨ Key Features

- **🛡️ Two Operation Modes:** 
  - **Malware & File Check Mode:** Provides a general-purpose forensic verdict for SOC analysts and incident responders.
  - **CTF Analysis & Helper Mode:** Augments findings with technique-specific hints and actionable command-line snippets for Capture The Flag challenges.
- **⚡ Pure Python Detectors:** Implements classic forensic utilities (`steghide`, `binwalk`, `strings`) natively in Python without relying on Linux binaries, ensuring 100% cross-platform compatibility!
- **📊 Interactive Scan History:** View, restore, and compare previous forensic scans seamlessly using local storage caching.
- **💡 Contextual Action Plans:** Suggests the next best forensic tool to run based on the exact anomalies detected in the file.

---

## 🔬 Supported Detection Engines

StegoScope runs files through multiple specialized engines simultaneously:

1. **Binwalk-style Signature Scanner (`detectors/binwalk.py`)**  
   Scans file bytes for embedded files by detecting standard magic byte headers (e.g., hidden ZIP or executable files within an image) at non-zero offsets.

2. **Passphrase LSB Extractor (`detectors/steghide.py`)**  
   Mimics `steghide`'s behavior by attempting standard passphrase-based LSB steganography extraction using seeded PRNGs.

3. **End of File (EOF) Analysis (`detectors/eof.py`)**  
   Identifies hidden payloads appended past the official end-of-file markers (like the `IEND` chunk in PNGs or `FF D9` in JPEGs).

4. **Error Level Analysis / ELA (`detectors/ela.py`)**  
   Detects digital tampering and copy-paste forgery in JPEGs by resaving the image at a known quality and highlighting differences.

5. **Audio Spectrogram & Audio LSB (`detectors/audio_spectrogram.py`, `audio_lsb.py`)**  
   Analyzes audio files (WAV, MP3) for visual anomalies embedded in frequency spectrograms and extracts Least Significant Bit data streams.

6. **Metadata & Strings Analysis (`detectors/metadata.py`, `strings.py`)**  
   Extracts EXIF data, hidden comments, and contiguous printable ASCII/Unicode strings embedded inside binary blobs.

---

## 🚀 Quick Start (Local Setup)

Want to run StegoScope locally? It takes less than 2 minutes.

### 1. Clone & Install
```bash
git clone https://github.com/rohanndhiman/StegoScope.git
cd StegoScope
pip install -r requirements.txt
```

### 2. Generate Sample Files (Optional)
We've included a script to generate safe, sample files with actual steganography hidden inside them so you can test the detectors immediately!
```bash
python generate_samples.py
```
*(This will populate the `samples/` directory with files like `lsb_hidden.png` and `suspicious_metadata.png`.)*

### 3. Start the Server
```bash
python app.py
```
Visit `http://localhost:5000` in your browser.

---

## ☁️ Deploying to Vercel

StegoScope is architected to be 100% compatible with Vercel's Serverless Functions out of the box!

1. Log in to [Vercel](https://vercel.com/) with your GitHub account.
2. Click **Add New...** → **Project**.
3. Import your cloned `StegoScope` repository.
4. Leave the Framework Preset as **Other**.
5. Click **Deploy**.

Vercel will automatically read the `vercel.json` file and map the Flask application via `@vercel/python`.

---

## 👨‍💻 Contributing

Contributions, issues, and feature requests are always welcome! Feel free to check the [issues page](https://github.com/rohanndhiman/StegoScope/issues).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---
<div align="center">
  <p>Built with ❤️ by <a href="https://github.com/rohanndhiman">Rohan Dhiman</a></p>
</div>
