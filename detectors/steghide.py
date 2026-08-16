"""
StegoScope — Passphrase LSB Extractor (Steghide-style)

Implements passphrase-based LSB steganography extraction.
Uses a SHA-256 hash of the passphrase to seed a deterministic PRNG.
This PRNG selects specific pixel/sample indices and generates a keystream
to XOR-decrypt the hidden payload, mimicking `steghide`'s behavior.
"""

import hashlib
import random
import numpy as np
from PIL import Image
import io
import soundfile as sf

def _extract_lsb_payload(data_array: np.ndarray, passphrase: str) -> str | None:
    """
    Extract and decrypt LSB payload using the passphrase.
    
    Args:
        data_array: Flattened 1D array of integers (pixels or audio samples).
        passphrase: Secret password.
        
    Returns:
        Decrypted text if valid printable ASCII, else None.
    """
    if not passphrase:
        return None
        
    # 1. Hash passphrase to get seed
    h = hashlib.sha256(passphrase.encode("utf-8")).digest()
    seed = int.from_bytes(h, "big")
    
    # 2. Seed PRNG
    prng = random.Random(seed)
    
    # 3. Read header (first 32 bits contain the payload length)
    n_data = len(data_array)
    if n_data < 256:  # too small
        return None
        
    # Generate 32 unique indices for the length header
    header_indices = prng.sample(range(n_data), 32)
    header_bits = []
    for idx in header_indices:
        header_bits.append(int(data_array[idx] & 1))
        
    # Reconstruct length integer (XORed with PRNG keystream)
    length_bytes = bytearray()
    for i in range(4):
        byte_val = 0
        for bit_idx in range(8):
            bit = header_bits[i * 8 + bit_idx]
            byte_val = (byte_val << 1) | bit
        # XOR decrypt with keystream
        length_bytes.append(byte_val ^ prng.randint(0, 255))
        
    payload_len = int.from_bytes(length_bytes, "big")
    
    # Sanity check: length must be reasonable
    if payload_len <= 0 or payload_len > 10000 or (payload_len * 8 + 32) > n_data:
        return None
        
    # 4. Read payload bits
    # Generate indices for payload by calling sample again
    payload_indices = prng.sample(range(n_data), payload_len * 8)
    
    payload_bits = []
    for idx in payload_indices:
        payload_bits.append(int(data_array[idx] & 1))
        
    # Reconstruct payload bytes
    payload_bytes = bytearray()
    for i in range(payload_len):
        byte_val = 0
        for bit_idx in range(8):
            bit = payload_bits[i * 8 + bit_idx]
            byte_val = (byte_val << 1) | bit
        payload_bytes.append(byte_val ^ prng.randint(0, 255))
        
    # 5. Verify printable ASCII
    try:
        decrypted_text = payload_bytes.decode("utf-8")
        # Check if characters are mostly printable ASCII
        printable_ratio = sum(32 <= ord(c) <= 126 or c in "\r\n\t" for c in decrypted_text) / len(decrypted_text)
        if printable_ratio > 0.95:
            return decrypted_text
    except Exception:
        pass
        
    return None


def analyze(file_bytes: bytes, file_type: str, passphrase: str = None) -> dict:
    """
    Run Steghide-style passphrase extraction.
    
    Args:
        file_bytes: Raw file bytes.
        file_type: File type string.
        passphrase: Secret password.
        
    Returns:
        Dict with name, score, explanation, and decrypted text.
    """
    if not passphrase:
        return {
            "name": "Passphrase Extraction",
            "score": 0,
            "explanation": "No passphrase provided. Passphrase-based LSB decryption was skipped.",
            "decrypted_text": None,
        }
        
    # Extract raw data array
    try:
        if file_type in ("png", "jpeg", "bmp"):
            img = Image.open(io.BytesIO(file_bytes)).convert("RGB")
            arr = np.array(img)
            # Use Red channel for stego
            data_array = arr[:, :, 0].flatten()
        else:
            # WAV or MP3 audio
            try:
                data_array, sr = sf.read(io.BytesIO(file_bytes), dtype='int16')
                if len(data_array.shape) > 1:
                    data_array = data_array[:, 0]
            except Exception:
                y, sr = librosa.load(io.BytesIO(file_bytes), sr=None, mono=True)
                data_array = (y * 32767).astype(np.int16)
    except Exception as e:
        return {
            "name": "Passphrase Extraction",
            "score": 0,
            "explanation": f"Could not parse file structure for decryption: {e}",
            "decrypted_text": None,
        }
        
    # Decrypt
    decrypted_text = _extract_lsb_payload(data_array, passphrase)
    
    if decrypted_text:
        score = 100
        explanation = (
            f"Successfully decrypted payload using passphrase '{passphrase}'! "
            f"Hidden data extracted successfully."
        )
    else:
        score = 0
        explanation = (
            f"LSB decryption attempted with passphrase '{passphrase}', "
            f"but no valid payload was decrypted. The password may be incorrect "
            f"or the file does not contain passphrase-protected data."
        )
        
    return {
        "name": "Passphrase Extraction",
        "score": score,
        "explanation": explanation,
        "decrypted_text": decrypted_text,
        "visualization": None,
    }
