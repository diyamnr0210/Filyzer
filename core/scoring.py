EXECUTABLE_TYPES = {"exe", "elf"}
NATURALLY_HIGH_ENTROPY = {"png", "jpeg", "zip", "gzip", "rar", "7z", "pdf"}
STRING_WEIGHTS = {"URL": 3, "IP address": 3, "PowerShell": 15,
                  "cmd.exe": 10, "Process-injection API": 20}
def score(r):
    s, why = 0, []
    if r.known_bad:
        s += 60
        why.append("Hash matches the known-bad list")
    if r.mismatch:
        s += 30
        why.append(f"Extension '{r.ext or 'none'}' does not match detected type '{r.detected_type}'")
        if r.detected_type in EXECUTABLE_TYPES:
            s += 20
            why.append("Executable disguised as another file type")
    if r.entropy > 7.5 and r.detected_type not in NATURALLY_HIGH_ENTROPY:
        s += 20
        why.append(f"Very high entropy ({r.entropy:.2f}/8): possibly encrypted or packed")
    for label in r.suspicious_strings:
        s += STRING_WEIGHTS.get(label, 5)
        why.append(f"Contains suspicious string pattern: {label}")
    s = min(s, 100)
    risk = "HIGH" if s >= 60 else "MEDIUM" if s >= 30 else "LOW"
    return s, risk, why
