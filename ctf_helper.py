"""
StegoScope — CTF & Forensic Helper / Suggestion Mapper

Rules-based interpretation layer that maps detector results to actionable
CTF technique suggestions or malware forensic remediation plans.
"""

# Thresholds for considering a detector signal as "strong" or "moderate"
STRONG_THRESHOLD = 70
MODERATE_THRESHOLD = 40


def get_ctf_suggestions(technique_results: list[dict], mode: str = "ctf") -> list[str]:
    """
    Map detector results to mode-specific technique suggestions or forensic next steps.
    
    Args:
        technique_results: List of dicts from each detector.
        mode: "ctf" or "malware".
    
    Returns:
        List of suggestion strings. Always returns at least one suggestion.
    """
    suggestions = []
    any_strong = False
    
    # Build a lookup by detector name for easy access
    results_by_name = {r["name"]: r for r in technique_results}
    is_ctf = (mode == "ctf")
    
    # -----------------------------------------------------------------------
    # Rule 1: LSB Analysis (image)
    # -----------------------------------------------------------------------
    lsb = results_by_name.get("LSB Analysis")
    if lsb and lsb["score"] >= STRONG_THRESHOLD:
        any_strong = True
        if is_ctf:
            suggestions.append(
                "**Strong LSB steganography signal detected.** Try these tools:\n"
                "  • **zsteg**: Run `zsteg -a <file>` to automatically test all channels and bit ordering variations.\n"
                "  • **Stegsolve**: Switch to the 'Stegsolve Explorer' tab or run the desktop jar to visually cycle through bit planes.\n"
                "  • **Manual Python Extraction**:\n"
                "    `from PIL import Image; img = Image.open('file.png'); bits = [p & 1 for p in img.getdata()]`"
            )
        else:
            suggestions.append(
                "**LSB Irregularity (High Confidence stego detected).** Action Plan:\n"
                "  • **High-entropy payload warning**: Bit distribution deviates significantly from natural camera or digital noise.\n"
                "  • **Remediation**: Extract LSB payload bytes to inspect for hidden executables, shellcode vectors, or encrypted configs.\n"
                "  • **Pristine Reference**: Compare color channel bit histograms against standard uncompressed templates to pinpoint modification locations."
            )
    elif lsb and lsb["score"] >= MODERATE_THRESHOLD:
        if is_ctf:
            suggestions.append(
                "**Moderate LSB anomaly.** LSB distribution is slightly skewed. "
                "Inspect specific channels (e.g. Red Bit 0 or Green Bit 0) under the 'Stegsolve Explorer' tab, or test with `zsteg -v -E <channel> <file>`."
            )
        else:
            suggestions.append(
                "**Moderate LSB Variance.** Slight pixel noise imbalance. Check for low-capacity data stuffing or minor watermarking metadata."
            )
            
    # -----------------------------------------------------------------------
    # Rule 2: Metadata Analysis
    # -----------------------------------------------------------------------
    meta = results_by_name.get("Metadata Analysis")
    if meta and meta["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or meta["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Metadata anomaly detected.** Investigate further:\n"
                "  • **Check EXIF comments**: Use `exiftool <file>` or `strings <file> | head -50` to inspect raw headers.\n"
                "  • **Check for encoded text**: Look for Base64 or Hex patterns in comments/maker notes, then decode with CyberChef.\n"
                "  • **Clear metadata**: Verify if clearing EXIF changes the file hash (`exiftool -all= <file>`)."
            )
        else:
            suggestions.append(
                "**Exif Metadata Tampering.** Suspicious headers detected:\n"
                "  • **Malformed structure**: EXIF segments contain invalid formats, excessive comment sizes, or software signature mismatches.\n"
                "  • **C2 Indicator**: Metadata fields are commonly utilized by droppers to execute payload strings.\n"
                "  • **Remediation**: Strip all EXIF segments (`exiftool -all= <file>`) before transferring or executing the file."
            )

    # -----------------------------------------------------------------------
    # Rule 3: Error Level Analysis
    # -----------------------------------------------------------------------
    ela = results_by_name.get("Error Level Analysis")
    if ela and ela["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or ela["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**ELA compression mismatch detected.**\n"
                "  • **Image Splicing**: Highlights areas with differing compression histories (composite overlays or cut-outs).\n"
                "  • **Action**: Zoom in on the ELA heatmap visualizer. Look for sharp, highly-detailed edges that should be soft.\n"
                "  • **Visual recovery**: Load in GIMP/Photoshop and adjust contrast/levels on the high-error region to highlight hidden details."
            )
        else:
            suggestions.append(
                "**Error Level Analysis Alert.** Splicing detected:\n"
                "  • **Modification indicators**: The file contains composite layers added post-compression. Suggests tampering or forged content.\n"
                "  • **Remediation**: Analyze the source/metadata of composite pixels. Verify integrity before trusting the image visually."
            )

    # -----------------------------------------------------------------------
    # Rule 4: Spectrogram Analysis
    # -----------------------------------------------------------------------
    spectro = results_by_name.get("Spectrogram Analysis")
    if spectro and spectro["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or spectro["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Spectrogram frequency band anomaly.**\n"
                "  • **Sonic Visualiser**: Open the audio file and add a 'Spectrogram' layer. Zoom in on flagged frequencies.\n"
                "  • **Hidden Images**: Check if the spectrogram graphs draw geometric shapes, letters, or QR flags in the frequency domain.\n"
                "  • **DTMF/Morse**: Check if high-frequency spikes contain DTMF dialing tones or Morse sequences."
            )
        else:
            suggestions.append(
                "**High-Frequency Spectrogram Anomaly.**\n"
                "  • **Signal Stuffing**: High frequency bands (>15kHz) show anomalous power levels. Often used to embed covert communications.\n"
                "  • **Action**: Filter audio via bandpass to isolate the suspicious frequency band. Verify if background noise is an active payload."
            )

    # -----------------------------------------------------------------------
    # Rule 5: Audio LSB Analysis
    # -----------------------------------------------------------------------
    audio_lsb = results_by_name.get("Audio LSB Analysis")
    if audio_lsb and audio_lsb["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or audio_lsb["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Audio LSB stego detected.** Try extraction tools:\n"
                "  • **WavSteg**: Extract LSB bits with `python3 -m wavsteg -r -i <file> -o output.txt`.\n"
                "  • **Steghide / OpenStego**: Check if the audio uses password LSB encryption: `steghide extract -sf <file>`.\n"
                "  • **Manual script**: Read raw sample values using Python's `wave` module, reassembling bit 0 of each sample into ASCII bytes."
            )
        else:
            suggestions.append(
                "**Covert Audio Channel.** Audio LSB bitstream manipulation:\n"
                "  • **LSB Tampering**: Audio amplitude sample LSBs exhibit non-random distribution. Indicates covert byte stuffing.\n"
                "  • **Remediation**: Re-encode audio to a lossy format (e.g., OGG/MP3) to destroy embedded LSB structures while preserving human audio."
            )

    # -----------------------------------------------------------------------
    # Rule 6: EOF Trailer Analysis
    # -----------------------------------------------------------------------
    eof = results_by_name.get("EOF Trailer Analysis")
    if eof and eof["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or eof["score"] >= STRONG_THRESHOLD
        trailing_size = eof.get("trailing_size", 0) or 0
        if is_ctf:
            suggestions.append(
                f"**EOF Trailer bytes detected ({trailing_size:,} bytes).**\n"
                "  • **Action**: Download the trailing bytes or inspect the hex preview.\n"
                "  • **Manual carving**: Extract bytes using `dd`:\n"
                "    `dd if=<file> of=extracted_payload.bin bs=1 skip=<offset_dec>`\n"
                "  • Check first bytes for standard headers like `PK\x03\x04` (ZIP) or `\xff\xd8` (JPEG)."
            )
        else:
            suggestions.append(
                f"**Appended Trailer Bytes Alert ({trailing_size:,} bytes).**\n"
                "  • **Dropper threat**: Files containing code/data appended after the standard EOF trailer (`IEND` for PNG, `FFD9` for JPEG) are common droppers.\n"
                "  • **Remediation**: Extract the appended bytes payload and compute its SHA-256 hash. Run reputation check on VirusTotal."
            )

    # -----------------------------------------------------------------------
    # Rule 7: Binwalk Signatures
    # -----------------------------------------------------------------------
    binw = results_by_name.get("Binwalk Signatures")
    if binw and binw["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or binw["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Embedded file signatures found (Polyglot).**\n"
                "  • **Action**: Open the 'Binwalk Extract' tab and click 'Extract Payload' to save the embedded file.\n"
                "  • **Linux CLI**: Carve files using `binwalk -e <file>` or extract with `foremost -i <file>`."
            )
        else:
            suggestions.append(
                "**Polyglot / Embedded Container detected.**\n"
                "  • **Masquerading threats**: Standard image or audio container hides nested file headers (e.g. ZIP, ELF, PDF) at non-zero offsets.\n"
                "  • **Remediation**: Extract embedded files and inspect in a secure Sandbox environment. Block the host file in firewalls."
            )

    # -----------------------------------------------------------------------
    # Rule 8: Strings Scan
    # -----------------------------------------------------------------------
    strs = results_by_name.get("Strings Scan")
    if strs and strs["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or strs["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Printable strings match suspected patterns.**\n"
                "  • **Action**: Navigate to the 'Strings Scan' tab and search for flags (e.g., `flag{`, `key{`, `STEGOSCOPE{`).\n"
                "  • Check for base64 strings or hex arrays and decode them.\n"
                "  • **CLI**: Run `strings -n 6 <file> | grep -i flag`."
            )
        else:
            suggestions.append(
                "**High-Suspicion Strings Found.**\n"
                "  • **Threat audit**: Extracted strings contain URLs, script commands, registry keys, or environment parameters.\n"
                "  • **Remediation**: Scan string variables against security signatures (YARA rules) to categorize threat families."
            )

    # -----------------------------------------------------------------------
    # Rule 9: Steghide Decrypt
    # -----------------------------------------------------------------------
    stegh = results_by_name.get("Steghide Decrypt")
    if stegh and stegh["score"] >= MODERATE_THRESHOLD:
        any_strong = any_strong or stegh["score"] >= STRONG_THRESHOLD
        if is_ctf:
            suggestions.append(
                "**Seeded LSB Steganography Suspected.**\n"
                "  • **Action**: Go to the 'Steghide Decrypt' tab and test common passwords (e.g. `stegoscope`, `flag`, `password`).\n"
                "  • **Password Cracking**: If password is unknown, run stegseek/stegcracker:\n"
                "    `stegseek --seed <file> rockyou.txt`"
            )
        else:
            suggestions.append(
                "**Password LSB Steganography Warning.**\n"
                "  • **Encrypted Covert Channel**: Pixel LSBs display high randomness consistent with encrypted steganographic blocks.\n"
                "  • **Remediation**: Recode or flatten image canvas layers (e.g., convert to JPEG and back) to scrub cover noise blocks."
            )

    # -----------------------------------------------------------------------
    # Fallback: No strong signals from any detector
    # -----------------------------------------------------------------------
    if not suggestions:
        if is_ctf:
            suggestions.append(
                "**No strong signals detected. Try fallback CTF methods:**\n"
                "  • **Check file type details**: Confirm the extension matches the true format: run `file <file>`.\n"
                "  • **Brute-force Steghide**: Run stegseek with common dictionaries.\n"
                "  • **Hex analysis**: Open in hex editor (`xxd <file> | less`) and scroll to the top and bottom to look for anomalies.\n"
                "  • **Color adjustments**: Adjust contrast/curves in GIMP to check for hidden foreground text overlays."
            )
        else:
            suggestions.append(
                "**File structure matches clean baselines.**\n"
                "  • **No covert payload suspected**: All goodness-of-fit scans, metadata formats, and byte trailers conform to typical baselines.\n"
                "  • **Actions**: None required. Normal digital document signature."
            )
    
    # Always add a general tip if we found something
    if any_strong and is_ctf:
        suggestions.append(
            "**CTF General Tip**: Chained encodings are common. If you extract base64 text or hex, run it through CyberChef decoders."
        )
    elif any_strong:
        suggestions.append(
            "**Remediation Tip**: Converting image formats (e.g., converting PNG to lossy JPG and back) destroys pixel LSB payloads."
        )
    
    return suggestions
