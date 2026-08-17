"""
StegoScope — Strings Extractor & Flag Scanner

Extracts printable ASCII strings (sequences of length >= 4) from binary data,
mimicking Linux's `strings` utility. Automatically scans strings for CTF flags.
"""

import re

# Simple regex to search for common flag signatures: e.g., FLAG{...}, STEGOSCOPE{...}
FLAG_REGEX = re.compile(r"([A-Za-z0-9_\-]{3,15}\{[A-Za-z0-9_\-\.\!\?]{5,80}\})")

def analyze(file_bytes: bytes, file_type: str) -> dict:
    """
    Extract ASCII strings from raw bytes and scan for CTF flags.
    
    Returns:
        Dict with name, score, explanation, list of strings, and details.
    """
    # Fast C-based regex extraction of printable ASCII sequences >= 4 chars
    ascii_regex = re.compile(b'[ -~]{4,}')
    matches = ascii_regex.findall(file_bytes)
    string_list = [m.decode('ascii') for m in matches]

    # Scan for flags
    flags_found = []
    for s in string_list:
        matches = FLAG_REGEX.findall(s)
        for m in matches:
            if m not in flags_found:
                flags_found.append(m)
                
    # Cap string list to first 250 entries to keep JSON payload performant
    total_strings_count = len(string_list)
    display_strings = string_list[:250]
    
    score = 98 if len(flags_found) > 0 else 0
    
    if score > 0:
        flags_str = ", ".join(flags_found)
        explanation = (
            f"Flag signature detected directly in ASCII strings! "
            f"Discovered flag: {flags_str}. Checked {total_strings_count:,} strings."
        )
    else:
        explanation = (
            f"Extracted {total_strings_count:,} printable ASCII strings. "
            "No obvious CTF flag formats detected."
        )
        
    return {
        "name": "Strings Search",
        "score": score,
        "explanation": explanation,
        "strings": display_strings,
        "total_count": total_strings_count,
        "flags_found": flags_found,
        "visualization": None,  # Text scrollable console in tab
    }
