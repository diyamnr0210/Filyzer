from pathlib import Path
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", 0, "png", {".png"}),
    (b"\xff\xd8\xff", 0, "jpeg", {".jpg", ".jpeg"}),
    (b"GIF8", 0, "gif", {".gif"}),
    (b"%PDF", 0, "pdf", {".pdf"}),
    (b"PK\x03\x04", 0, "zip", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"MZ", 0, "exe", {".exe", ".dll", ".sys", ".scr"}),
    (b"\x7fELF", 0, "elf", {"", ".so", ".elf", ".bin", ".o"}),
    (b"Rar!\x1a\x07", 0, "rar", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z", {".7z"}),
    (b"\x1f\x8b", 0, "gzip", {".gz", ".tgz"}),
    (b"SQLite format 3\x00", 0, "sqlite", {".db", ".sqlite", ".sqlite3"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "ole", {".doc", ".xls", ".ppt", ".msi"}),
]
def identify(path):
    with open(path, "rb") as f:
        head = f.read(32)
    for magic, offset, name, exts in SIGNATURES:
        if head[offset:offset + len(magic)] == magic:
            return name, exts
    return "unknown", None
def check_extension(path):
    name, exts = identify(path)
    if exts is None:
        return name, False
    return name, Path(path).suffix.lower() not in exts
