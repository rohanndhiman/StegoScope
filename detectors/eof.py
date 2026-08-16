"""
StegoScope — EOF & Trailing Bytes Detector

Scans files for trailing bytes appended after the standard file format EOF
(End-Of-File) marker. This is a classic CTF steganography technique used
to hide zip archives, text payloads, or secondary files.
"""

import base64

def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Scan for bytes appended past the natural file format EOF marker.
    
    Returns:
        Dict with name, score, explanation, and visual-preview/payload data.
    """
    file_len = len(file_bytes)
    eof_offset = file_len  # default to no trailing bytes
    
    if file_type == "png":
        # PNG ends with the IEND chunk: length 0 (4 bytes), type 'IEND' (4 bytes), CRC (4 bytes).
        # Standard signature is b"IEND\xae\x42\x60\x82"
        idx = file_bytes.rfind(b"IEND\xae\x42\x60\x82")
        if idx != -1:
            eof_offset = idx + 8  # 4 bytes for IEND + 4 bytes for CRC
            
    elif file_type == "jpeg":
        # JPEG ends with \xFF\xD9 (EOI - End of Image marker)
        idx = file_bytes.rfind(b"\xff\xd9")
        if idx != -1:
            eof_offset = idx + 2
            
    elif file_type == "bmp":
        # BMP header size is at offset 2 (4 bytes, little endian)
        if file_len > 54:
            size_field = int.from_bytes(file_bytes[2:6], byteorder="little")
            # Some encoders write 0 or invalid sizes, but if valid:
            if 54 < size_field <= file_len:
                eof_offset = size_field
                
    elif file_type == "wav":
        # WAV has a chunk size field at offset 4 (4 bytes, little endian) representing file size - 8
        if file_len > 44:
            riff_size = int.from_bytes(file_bytes[4:8], byteorder="little")
            size_field = riff_size + 8
            if 44 < size_field <= file_len:
                eof_offset = size_field

    # Compute trailing bytes
    trailing_size = file_len - eof_offset
    
    # If the trailing size is very small (e.g. less than 4 bytes in JPEG/PNG due to padding/metadata alignment),
    # we ignore it to avoid false positives.
    if trailing_size > 4:
        score = 95
        payload = file_bytes[eof_offset:]
        payload_b64 = base64.b64encode(payload).decode("ascii")
        
        # Build hex/ASCII preview
        preview_bytes = payload[:64]
        hex_lines = []
        for i in range(0, len(preview_bytes), 16):
            chunk = preview_bytes[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")
            
        hex_preview = "\n".join(hex_lines)
        explanation = (
            f"Detected {trailing_size:,} bytes of trailing data appended past "
            f"the natural End-Of-File marker (offset {eof_offset:,}). "
            "This strongly indicates hidden stego payloads or embedded polyglot archives."
        )
    else:
        score = 0
        payload_b64 = None
        hex_preview = None
        explanation = "No trailing data detected past the natural End-Of-File marker."

    return {
        "name": "EOF Trail Scan",
        "score": score,
        "explanation": explanation,
        "trailing_size": trailing_size if trailing_size > 4 else 0,
        "hex_preview": hex_preview,
        "payload_b64": payload_b64,
        "visualization": None,  # Displayed as text/hex preview
    }
