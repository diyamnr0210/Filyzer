import re
PATTERNS = {
    "URL": rb"https?://[\x21-\x7e]+",
    "IP address": rb"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "PowerShell": rb"powershell",
    "cmd.exe": rb"cmd\.exe",
    "Process-injection API": rb"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory",
}
def _head(path, max_bytes):
    with open(path, "rb") as f:
        return f.read(max_bytes)
def suspicious_strings(path, max_bytes=5 * 1024 * 1024):
    data = _head(path, max_bytes)
    return [label for label, pat in PATTERNS.items() if re.search(pat, data, re.I)]
def extract_strings(path, min_len=6, limit=200, max_bytes=5 * 1024 * 1024):
    data = _head(path, max_bytes)
    found = re.findall(rb"[ -~]{%d,}" % min_len, data)
    return [s.decode("ascii") for s in found[:limit]]
