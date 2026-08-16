"""
StegoScope — Demo Sample Generator

Creates a set of sample files in the /samples directory for demonstration:
- 2 clean images (no hidden data)
- 1 image with LSB-embedded text
- 1 image with suspicious/stuffed metadata
- 1 clean audio file (sine wave)
- 1 audio file with LSB-embedded data

Run: python generate_samples.py
"""

import os
import io
import wave
import math
import hashlib
import random
import numpy as np
from PIL import Image



SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def ensure_dir():
    """Create samples directory if it doesn't exist."""
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    print(f"[+] Samples directory: {SAMPLES_DIR}")


# ---------------------------------------------------------------------------
# Image generators
# ---------------------------------------------------------------------------

def create_gradient_image(width=640, height=480):
    """Create a smooth gradient image (clean, no hidden data)."""
    img = Image.new("RGB", (width, height))
    pixels = img.load()
    for y in range(height):
        for x in range(width):
            r = int(255 * x / width)
            g = int(255 * y / height)
            b = int(255 * (1 - x / width))
            pixels[x, y] = (r, g, b)
    return img


def create_pattern_image(width=640, height=480):
    """Create a geometric pattern image (clean, no hidden data)."""
    arr = np.zeros((height, width, 3), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            # Checkerboard with gradient
            block = 32
            checker = ((x // block) + (y // block)) % 2
            base_r = int(40 + 100 * (x / width))
            base_g = int(60 + 80 * (y / height))
            base_b = int(120 + 60 * ((x + y) / (width + height)))
            if checker:
                arr[y, x] = [base_r + 40, base_g + 30, base_b + 20]
            else:
                arr[y, x] = [base_r, base_g, base_b]
    return Image.fromarray(arr)


def embed_lsb_text(img, message):
    """
    Embed a pseudo-random bit sequence into the LSBs of the red channel.
    Using a fixed seed ensures the distribution is uniformly 50/50 (simulating
    an encrypted/compressed stego payload) and perfectly reproducible.
    """
    arr = np.array(img)
    flat = arr[:, :, 0].flatten()
    
    # Generate reproducible pseudo-random bits
    np.random.seed(1337)
    random_bits = np.random.randint(0, 2, size=len(flat))
    
    # Work in int32 to avoid overflow/underflow, then cast back to uint8
    work = flat.astype(np.int32)
    for i in range(len(flat)):
        work[i] = (work[i] & ~1) | int(random_bits[i])
        
    arr[:, :, 0] = work.astype(np.uint8).reshape(arr.shape[:2])
    return Image.fromarray(arr)


def embed_steghide_stego(img, message, passphrase):
    """
    Embed a message using passphrase-protected LSB stego.
    Corresponds exactly to detectors/steghide.py decryption.
    """
    arr = np.array(img)
    flat = arr[:, :, 0].flatten()
    n_data = len(flat)
    
    # 1. Generate seed
    h = hashlib.sha256(passphrase.encode("utf-8")).digest()
    seed = int.from_bytes(h, "big")
    prng = random.Random(seed)
    
    # 2. Get header indices first (before any randint calls)
    header_indices = prng.sample(range(n_data), 32)
    
    # 3. Build length header and XOR encrypt it
    payload_bytes = message.encode("utf-8")
    payload_len = len(payload_bytes)
    length_bytes = payload_len.to_bytes(4, byteorder="big")
    encrypted_header_bytes = bytearray(b ^ prng.randint(0, 255) for b in length_bytes)
    
    # Convert header to bit string (length 32)
    header_bits = []
    for b in encrypted_header_bytes:
        for bit_idx in range(8):
            bit = (b >> (7 - bit_idx)) & 1
            header_bits.append(bit)
            
    # 4. Get payload indices next (before payload encryption randint calls)
    payload_indices = prng.sample(range(n_data), payload_len * 8)
    
    # 5. XOR encrypt payload
    encrypted_payload_bytes = bytearray(b ^ prng.randint(0, 255) for b in payload_bytes)
    
    # Convert payload to bit string
    payload_bits = []
    for b in encrypted_payload_bytes:
        for bit_idx in range(8):
            bit = (b >> (7 - bit_idx)) & 1
            payload_bits.append(bit)
            
    # 6. Assemble indices and bits
    indices = header_indices + payload_indices
    all_bits = header_bits + payload_bits
    
    if len(all_bits) > n_data:
        raise ValueError("Payload too large for this image channel")
        
    # 7. Embed LSBs
    work = flat.astype(np.int32)
    for i, idx in enumerate(indices):
        work[idx] = (work[idx] & ~1) | all_bits[i]
        
    arr[:, :, 0] = work.astype(np.uint8).reshape(arr.shape[:2])
    return Image.fromarray(arr)


def create_suspicious_metadata_image_manual(width=640, height=480):
    """
    Create a JPEG with suspicious metadata by writing custom EXIF.
    Uses Pillow's info dict for PNG metadata, or manually constructs
    EXIF for JPEG.
    """
    img = create_gradient_image(width, height)
    
    # For simplicity, save as PNG with a large text chunk
    # (PNG text chunks are a common place to hide data)
    from PIL import PngImagePlugin
    
    info = PngImagePlugin.PngInfo()
    # Normal metadata
    info.add_text("Software", "Adobe Photoshop CC 2024")
    info.add_text("Author", "Unknown")
    
    # Suspicious: unusually large comment field with hidden text
    hidden_payload = (
        "This is a hidden message embedded in the metadata field. "
        "In a real CTF challenge, this could contain a flag, a URL, "
        "a Base64-encoded file, or other concealed information. "
        "Flag: STEGOSCOPE{m3t4d4t4_h1d1ng_1n_pl41n_s1ght} "
    )
    # Pad to make it suspiciously large
    hidden_payload = hidden_payload * 10
    info.add_text("Comment", hidden_payload)
    info.add_text("Description", "A normal landscape photograph. Nothing to see here.")
    
    return img, info


# ---------------------------------------------------------------------------
# Audio generators
# ---------------------------------------------------------------------------

def create_sine_wave(filename, duration=3.0, freq=440.0, sample_rate=22050):
    """Create a clean WAV file with a sine wave tone."""
    n_samples = int(duration * sample_rate)
    samples = []
    for i in range(n_samples):
        t = i / sample_rate
        # Mix of frequencies for a more natural sound
        value = 0.5 * math.sin(2 * math.pi * freq * t)
        value += 0.2 * math.sin(2 * math.pi * (freq * 1.5) * t)
        value += 0.1 * math.sin(2 * math.pi * (freq * 2) * t)
        # Fade in/out
        fade_len = int(0.1 * sample_rate)
        if i < fade_len:
            value *= i / fade_len
        elif i > n_samples - fade_len:
            value *= (n_samples - i) / fade_len
        samples.append(value)
    
    # Normalize and convert to 16-bit
    samples = np.array(samples, dtype=np.float64)
    samples = samples / np.max(np.abs(samples)) * 0.8
    int_samples = (samples * 32767).astype(np.int16)
    
    # Write WAV
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)  # 16-bit
        wav.setframerate(sample_rate)
        wav.writeframes(int_samples.tobytes())
    
    return int_samples


def create_lsb_audio(filename, message, duration=3.0, freq=440.0, sample_rate=22050):
    """Create a WAV file with pseudo-random LSBs to simulate an encrypted payload."""
    n_samples = int(duration * sample_rate)
    samples = []
    for i in range(n_samples):
        t = i / sample_rate
        value = 0.5 * math.sin(2 * math.pi * freq * t)
        value += 0.2 * math.sin(2 * math.pi * (freq * 1.5) * t)
        fade_len = int(0.1 * sample_rate)
        if i < fade_len:
            value *= i / fade_len
        elif i > n_samples - fade_len:
            value *= (n_samples - i) / fade_len
        samples.append(value)
    
    samples = np.array(samples, dtype=np.float64)
    samples = samples / np.max(np.abs(samples)) * 0.8
    int_samples = (samples * 32767).astype(np.int16)
    
    # Generate reproducible pseudo-random bits
    np.random.seed(1337)
    random_bits = np.random.randint(0, 2, size=len(int_samples))
    
    # Work in int32 to avoid overflow with bitmask operations on signed int16
    work = int_samples.astype(np.int32)
    for i in range(len(int_samples)):
        work[i] = (work[i] & ~1) | int(random_bits[i])
    int_samples = work.astype(np.int16)
    
    # Write WAV
    with wave.open(filename, 'w') as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)
        wav.writeframes(int_samples.tobytes())




# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ensure_dir()
    
    # --- Clean images ---
    print("[+] Creating clean_photo.png (gradient image)...")
    clean1 = create_gradient_image()
    clean1.save(os.path.join(SAMPLES_DIR, "clean_photo.png"))
    
    print("[+] Creating clean_landscape.png (pattern image)...")
    clean2 = create_pattern_image()
    clean2.save(os.path.join(SAMPLES_DIR, "clean_landscape.png"))
    
    # --- LSB-embedded image ---
    print("[+] Creating lsb_hidden.png (LSB-embedded text)...")
    base_img = create_gradient_image()
    hidden_msg = (
        "StegoScope Demo: This text was hidden using LSB steganography. "
        "In a real-world scenario, this could be a secret message, "
        "a password, or embedded binary data. "
        "Flag: STEGOSCOPE{lsb_st3g0_d3t3ct3d}"
    )
    lsb_img = embed_lsb_text(base_img, hidden_msg)
    lsb_img.save(os.path.join(SAMPLES_DIR, "lsb_hidden.png"))
    
    # --- Suspicious metadata image ---
    print("[+] Creating suspicious_metadata.png (stuffed metadata)...")
    meta_img, meta_info = create_suspicious_metadata_image_manual()
    meta_img.save(os.path.join(SAMPLES_DIR, "suspicious_metadata.png"), pnginfo=meta_info)
    
    # --- Passphrase Stego image ---
    print("[+] Creating steghide_hidden.png (passphrase-embedded)...")
    base_img = create_gradient_image()
    steghide_msg = "STEGOSCOPE{steghide_pass_decrypted_successfully}"
    steghide_img = embed_steghide_stego(base_img, steghide_msg, "stegoscope")
    # Also append trailing bytes (ZIP payload) to it to trigger binwalk and trailing scan!
    # Let's make it a double-payload: both passphrase LSB and trailing ZIP data!
    # This simulates a complex CTF file that shows off multiple tools at once.
    # Standard 4-byte ZIP start signature + mock data + end
    fake_zip = b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00FakeZIPFileForStegoScopeForensicDemonstrationPK\x05\x06"
    
    # Save to buffer, then append zip bytes
    buf = io.BytesIO()
    steghide_img.save(buf, format="PNG")
    png_bytes = buf.getvalue()
    
    # Write directly to file with trailing zip appended
    with open(os.path.join(SAMPLES_DIR, "steghide_hidden.png"), "wb") as f:
        f.write(png_bytes + fake_zip)

    
    # --- Clean audio ---
    print("[+] Creating clean_audio.wav (sine wave)...")
    create_sine_wave(os.path.join(SAMPLES_DIR, "clean_audio.wav"))
    
    # --- LSB audio ---
    print("[+] Creating lsb_audio.wav (LSB-embedded message)...")
    audio_msg = "STEGOSCOPE{aud10_lsb_h1dd3n}"
    create_lsb_audio(os.path.join(SAMPLES_DIR, "lsb_audio.wav"), audio_msg)
    
    print()
    print("=" * 50)
    print("  Sample generation complete!")
    print(f"  Files saved to: {SAMPLES_DIR}")
    print("=" * 50)
    print()
    print("  Files created:")
    for f in sorted(os.listdir(SAMPLES_DIR)):
        fpath = os.path.join(SAMPLES_DIR, f)
        size = os.path.getsize(fpath)
        print(f"    {f:30s} {size:>10,} bytes")


if __name__ == "__main__":
    main()
