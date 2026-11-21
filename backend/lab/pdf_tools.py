"""
pdf_tools.py - build small, valid, deterministic PDF documents for the Security Lab.

The lab signs real PDF bytes (the same kind of file SecureSign users sign), not
plain strings. The output is deterministic: the same text always gives the same
bytes, so a SHA-256 fingerprint shown in the GUI can be reproduced offline.
Only the standard library is used.
"""

TITLE = "SecureSign Security Lab"


def _escape(text: str) -> str:
    # PDF literal strings: escape backslash and parentheses; keep to Latin-1.
    safe = text.encode("latin-1", "replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(body: str, title: str = TITLE) -> bytes:
    """Return a one-page A4 PDF that shows `title` and the lines of `body`."""
    lines = [title, ""] + body.splitlines()
    ops = ["BT", "/F1 18 Tf", "72 770 Td", "22 TL"]
    for i, line in enumerate(lines):
        if i == 1:
            ops.append("/F1 12 Tf")
        ops.append(f"({_escape(line)}) Tj T*")
    ops.append("ET")
    stream = "\n".join(ops).encode("latin-1")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)
