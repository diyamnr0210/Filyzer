import hashlib
def file_hashes(path, chunk_size=1 << 20):
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
