"""
StegoScope — Binwalk-style Signature Scanner

Scans file bytes for embedded files by detecting standard file format headers
(magic bytes) at non-zero offsets, mimicking Linux's `binwalk` utility.
Supports extracting and downloading the discovered payloads.
"""

import base64

# Common magic byte signatures
SIGNATURES = {
    b"PK\x03\x04":             ("ZIP archive", ".zip"),
    b"\x89PNG\r\n\x1a\n":     ("PNG image", ".png"),
    b"\xff\xd8\xff":           ("JPEG image", ".jpg"),
    b"7z\xbc\xaf\x27\x1c":     ("7z archive", ".7z"),
    b"\x1f\x8b":               ("GZIP archive", ".gz"),
    b"\x7fELF":                ("ELF Executable", ".elf"),
    b"%PDF":                   ("PDF Document", ".pdf"),
}

def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Scan for embedded files at non-zero offsets.
    
    Returns:
        Dict with name, score, explanation, and a list of detected embedded files.
    """
    detected_files = []
    file_len = len(file_bytes)
    
    # Scan for each signature
    for sig, (name, ext) in SIGNATURES.items():
        offset = 0
        while True:
            offset = file_bytes.find(sig, offset)
            if offset == -1:
                break
            
            # Avoid flagging the host file's own header at offset 0
            if offset > 0:
                # Estimate embedded file size if possible
                end_offset = file_len
                
                # PNG size estimation (find next IEND chunk)
                if sig == b"\x89PNG\r\n\x1a\n":
                    iend_idx = file_bytes.find(b"IEND\xae\x42\x60\x82", offset)
                    if iend_idx != -1:
                        end_offset = iend_idx + 8
                        
                # JPEG size estimation (find next EOI marker)
                elif sig == b"\xff\xd8\xff":
                    eoi_idx = file_bytes.find(b"\xff\xd9", offset)
                    if eoi_idx != -1:
                        end_offset = eoi_idx + 2
                
                embedded_size = end_offset - offset
                payload = file_bytes[offset:end_offset]
                payload_b64 = base64.b64encode(payload).decode("ascii")
                
                detected_files.append({
                    "offset": offset,
                    "type": name,
                    "extension": ext,
                    "size": embedded_size,
                    "payload_b64": payload_b64,
                })
                
            offset += len(sig)  # move past signature to find next occurrences

    # Sort detected files by offset
    detected_files.sort(key=lambda x: x["offset"])
    
    score = 90 if len(detected_files) > 0 else 0
    
    if score > 0:
        details = ", ".join(f"{f['type']} at offset {f['offset']:,} ({f['size']:,} bytes)" for f in detected_files)
        explanation = f"Detected {len(detected_files)} embedded files inside this payload: {details}."
    else:
        explanation = "No embedded files or foreign magic signatures detected at non-zero offsets."
        
    return {
        "name": "Binwalk Scan",
        "score": score,
        "explanation": explanation,
        "detected_files": detected_files,
        "visualization": None,  # Displayed in tab table
    }
