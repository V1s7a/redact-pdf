#!/usr/bin/env python3
"""
Smoke test: builds fake medical records (text page, filled form field, scanned
page, metadata, embedded file, DoD identifiers), redacts them, and fails if any
fake identifier is still extractable or clinical content was lost.

All data here is invented. Generated PDFs go to a temp folder and are deleted.
Run:  .venv/bin/python tests/smoke_test.py
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import pymupdf

ROOT = Path(__file__).resolve().parent.parent

SECRETS = [
    "Margaret", "Thornton", "Okafor", "03/14/1962", "RG00482913", "4127 Willow Creek",
    "23502", "555-0148", "m.thornton62@example.com", "524-71-9083", "XKH448201937",
    "1467382910", "BCX9930021",
    "Whitfield", "1384729561", "1029384756", "1572839460", "1666123987",
    "28 441 902", "1748291053", "10293847561", "512-44-7781",
]
MUST_KEEP = ["aspirin 325 mg", "Troponin was negative", "Atypical chest pain",
             "64 year old", "Pulse 72", "Lipid panel"]

PAGE1 = """RIVERSIDE GENERAL HOSPITAL - DISCHARGE SUMMARY
Patient Name: Margaret A. Thornton
DOB: 03/14/1962          MRN: RG00482913
Address: 4127 Willow Creek Drive, Apt 3B, Norfolk, VA 23502
Phone: (757) 555-0148     Email: m.thornton62@example.com
SSN: 524-71-9083          Member ID: XKH448201937
Attending: Dr. Samuel Okafor, NPI 1467382910

HISTORY OF PRESENT ILLNESS
Ms. Thornton is a 64 year old female who presented with chest pain.
She was given aspirin 325 mg and nitroglycerin. Troponin was negative x2.
Diagnosis: Atypical chest pain, hypertension."""

SCANNED = """LAB REQUISITION
Patient: Margaret Thornton   DOB: 03/14/1962
MRN: RG00482913   Insurance ID: BCX9930021
Tests: CBC, CMP, Lipid panel, HbA1c"""

PAGE3 = """MILITARY TREATMENT FACILITY - ENCOUNTER NOTE
Patient: SSgt Daniel R. Whitfield
DoD ID: 1384729561
FMP/Sponsor SSN: 20/512-44-7781
EDIPI 1029384756
CAC #: 1572839460
DBIDS ID 1666123987
VA File Number: 28 441 902
Member presented for follow-up. His EDIPI is 1748291053 per DEERS.
Spouse dependent, DoD Benefits Number 10293847561.
Pulse 72, BP 128/82."""


def build(path: Path) -> None:
    doc = pymupdf.open()
    p1 = doc.new_page()
    p1.insert_text((50, 60), PAGE1, fontsize=10)
    w = pymupdf.Widget()
    w.field_name, w.field_type = "emergency_contact", pymupdf.PDF_WIDGET_TYPE_TEXT
    w.field_value, w.rect = "Robert Thornton 757-555-0177", pymupdf.Rect(50, 300, 350, 320)
    p1.add_widget(w)

    tmp = pymupdf.open()
    tp = tmp.new_page()
    tp.insert_text((50, 60), SCANNED, fontsize=12)
    p2 = doc.new_page()
    p2.insert_image(p2.rect, pixmap=tp.get_pixmap(dpi=200))  # image only, no text layer

    doc.new_page().insert_text((50, 60), PAGE3, fontsize=10)
    doc.set_metadata({"title": "Discharge - Margaret Thornton", "author": "Samuel Okafor MD"})
    doc.embfile_add("notes.txt", b"Margaret Thornton SSN 524-71-9083")
    doc.save(path)


def extract(path: Path) -> str:
    sys.path.insert(0, str(ROOT))
    import redact_pdf  # noqa: E402
    doc = pymupdf.open(path)
    parts = [str(doc.metadata), doc.get_xml_metadata()]
    for page in doc:
        parts.append(page.get_text())
        parts.append(redact_pdf.ocr_text(page).text)  # catch anything left in images
    parts.append(f"embedded={doc.embfile_count()}")
    return "\n".join(parts)


def main() -> int:
    with tempfile.TemporaryDirectory() as d:
        src, out = Path(d) / "fake.pdf", Path(d) / "fake_redacted.pdf"
        build(src)
        r = subprocess.run([sys.executable, "-W", "ignore", str(ROOT / "redact_pdf.py"),
                            str(src), str(out)], capture_output=True, text=True)
        print(r.stdout.strip())
        if r.returncode != 0:
            print(r.stderr, file=sys.stderr)
            print("FAIL: redact_pdf.py exited with", r.returncode)
            return 1
        text = extract(out)
        leaked = [s for s in SECRETS if s in text]
        lost = [s for s in MUST_KEEP if s not in text]
        if "embedded=0" not in text:
            leaked.append("<embedded file>")
        if leaked:
            print("FAIL: still present after redaction:", leaked)
        if lost:
            print("FAIL: clinical content removed:", lost)
        if leaked or lost:
            return 1
    print(f"PASS: {len(SECRETS)} fake identifiers removed, clinical content kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
