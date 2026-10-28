import html
from datetime import datetime
def describe(r):
    lines = [
        f"Path:      {r.path}",
        f"Type:      {r.detected_type}   (extension: {r.ext or 'none'})",
        f"Size:      {r.size} bytes",
        f"Entropy:   {r.entropy:.2f} / 8",
        f"MD5:       {r.md5}",
        f"SHA-256:   {r.sha256}",
        f"Risk:      {r.risk} ({r.score}/100)",
    ]
    if r.error:
        lines.append(f"Error:     {r.error}")
    if r.reasons:
        lines += ["", "Why:"] + [f"  - {x}" for x in r.reasons]
    if r.meta:
        lines += ["", "Timestamps:"] + [f"  {k}: {v}" for k, v in r.meta.items() if k != "size"]
    if r.exif:
        lines += ["", "EXIF:"] + [f"  {k}: {v}" for k, v in r.exif.items()]
    return "\n".join(lines)
def export_html(reports, out_path):
    rows = ""
    for r in sorted(reports, key=lambda x: x.score, reverse=True):
        why = "<br>".join(html.escape(x) for x in r.reasons) or "-"
        rows += (f"<tr class='{r.risk}'><td>{html.escape(r.path)}</td>"
                 f"<td>{html.escape(r.detected_type)}</td><td>{r.entropy:.2f}</td>"
                 f"<td>{r.risk} ({r.score})</td><td>{why}</td>"
                 f"<td><code>{r.sha256[:16]}...</code></td></tr>")
    page = f"""<!doctype html><meta charset="utf-8"><title>Forensic Report</title>
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}}
.HIGH{{background:#f8c9c9}}.MEDIUM{{background:#fdebc0}}.LOW{{background:#d9f2d9}}</style>
<h1>Forensic File Analysis Report</h1>
<p>Generated {datetime.now():%Y-%m-%d %H:%M:%S}. Files analyzed: {len(reports)}</p>
<table><tr><th>File</th><th>Type</th><th>Entropy</th><th>Risk</th><th>Reasons</th><th>SHA-256</th></tr>
{rows}</table>"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(page)
