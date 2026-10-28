import os
from datetime import datetime
def _fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
def basic_metadata(path):
    st = os.stat(path)
    return {
        "size": st.st_size,
        "modified": _fmt(st.st_mtime),
        "accessed": _fmt(st.st_atime),
        "changed/created": _fmt(st.st_ctime),
    }
def read_exif(path):
    try:
        from PIL import Image, ExifTags
        with Image.open(path) as img:
            return {ExifTags.TAGS.get(k, str(k)): str(v)[:100]
                    for k, v in img.getexif().items()}
    except Exception:  
        return {}