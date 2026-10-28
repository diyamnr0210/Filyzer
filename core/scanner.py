import os
from dataclasses import dataclass, field
from pathlib import Path
from . import entropy, hashing, metadata, scoring, signatures, strings_extract
@dataclass
class FileReport:
    path: str
    ext: str = ""
    size: int = 0
    detected_type: str = "unknown"
    mismatch: bool = False
    md5: str = ""
    sha256: str = ""
    entropy: float = 0.0
    meta: dict = field(default_factory=dict)
    exif: dict = field(default_factory=dict)
    suspicious_strings: list = field(default_factory=list)
    known_bad: bool = False
    score: int = 0
    risk: str = "LOW"
    reasons: list = field(default_factory=list)
    error: str = ""
def analyze_file(path, bad_hashes=frozenset()):
    p = Path(path)
    r = FileReport(path=str(p), ext=p.suffix.lower())
    try:
        r.meta = metadata.basic_metadata(p)
        r.size = r.meta["size"]
        r.detected_type, r.mismatch = signatures.check_extension(p)
        h = hashing.file_hashes(p)
        r.md5, r.sha256 = h["md5"], h["sha256"]
        r.known_bad = r.sha256 in bad_hashes or r.md5 in bad_hashes
        r.entropy = entropy.file_entropy(p)
        r.exif = metadata.read_exif(p)
        r.suspicious_strings = strings_extract.suspicious_strings(p)
        r.score, r.risk, r.reasons = scoring.score(r)
    except OSError as e:
        r.error = str(e)
    return r
def collect_files(root):
    if os.path.isfile(root):
        return [root]
    return [os.path.join(d, f) for d, _, files in os.walk(root) for f in files]
