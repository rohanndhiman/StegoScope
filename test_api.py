"""Quick API test script for StegoScope."""
import requests
import sys
import json

# Reconfigure stdout to use UTF-8 to prevent encoding crashes on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


BASE = "http://localhost:8080"

test_files = [
    ("samples/lsb_hidden.png", "malware", "LSB embedded image"),
    ("samples/clean_photo.png", "malware", "Clean gradient image"),
    ("samples/suspicious_metadata.png", "malware", "Suspicious metadata image"),
    ("samples/lsb_hidden.png", "ctf", "LSB image in CTF mode"),
    ("samples/clean_audio.wav", "malware", "Clean audio"),
    ("samples/lsb_audio.wav", "ctf", "LSB audio in CTF mode"),
]

print("=" * 70)
print("  StegoScope API Tests")
print("=" * 70)

all_pass = True
for filepath, mode, description in test_files:
    print(f"\n--- {description} ---")
    print(f"    File: {filepath}  |  Mode: {mode}")
    try:
        with open(filepath, "rb") as f:
            r = requests.post(
                f"{BASE}/analyze",
                files={"file": f},
                data={"mode": mode},
            )
        if r.status_code != 200:
            print(f"    ERROR: status {r.status_code}")
            print(f"    {r.text[:200]}")
            all_pass = False
            continue

        d = r.json()
        print(f"    Overall: {d['overall_score']}% ({d['overall_label']})")
        for t in d["techniques"]:
            viz = "yes" if t.get("visualization") else "no"
            print(f"      {t['name']:25s} score={t['score']:3d}  viz={viz}")
            print(f"        {t['explanation'][:90]}")
        
        if "ctf_suggestions" in d:
            print(f"    CTF suggestions: {len(d['ctf_suggestions'])} items")
            for s in d["ctf_suggestions"]:
                print(f"      -> {s[:80]}...")
    except Exception as e:
        print(f"    EXCEPTION: {e}")
        all_pass = False

# Test error handling
print(f"\n--- Error test: unsupported file ---")
try:
    with open("app.py", "rb") as f:
        r = requests.post(f"{BASE}/analyze", files={"file": f}, data={"mode": "malware"})
    print(f"    Status: {r.status_code}  (expected 415)")
    print(f"    {r.json().get('error', 'no error key')}")
except Exception as e:
    print(f"    EXCEPTION: {e}")

print("\n" + "=" * 70)
print(f"  Result: {'ALL PASS' if all_pass else 'SOME FAILURES'}")
print("=" * 70)
