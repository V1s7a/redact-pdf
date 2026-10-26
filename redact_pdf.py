#!/usr/bin/env python3
"""
redact_pdf.py - Detect and truly remove PHI/PII from an entire PDF, then verify.

What it does, page by page:
  1. Bakes form fields and annotations into the page so their values get scanned too.
  2. Reads the text layer. Pages that look scanned (little text, or mostly image)
     are also OCR'd with Tesseract so text inside images is caught.
  3. Finds PHI/PII three ways:
       - Microsoft Presidio (spaCy NER + built-in recognizers: names, SSN,
         phone, email, dates, locations, licenses, card/bank numbers, IPs, URLs)
       - Labeled fields common in medical records ("MRN:", "DOB:", "Member ID:",
         "Patient Name:", ...). Everything after the label on that line is redacted.
       - An optional deny list of terms you always want gone (patient name variants, etc.)
  4. Applies real redactions: text under each box is deleted from the content
     stream and image pixels under it are blanked. Nothing is just covered.
  5. Scrubs metadata, XMP, bookmarks, links, JavaScript, embedded files,
     thumbnails and hidden text, then rewrites the whole file (no incremental history).
  6. Optional --flatten rasterizes every page so no text layer survives at all.
  7. Verifies the output: re-extracts (and re-OCRs) every page, checks that no
     redacted value is still present, and re-runs detection to report residual hits.
     Exits non-zero if a leak is found.

The JSON report lists entity TYPES, counts and pages only. It never records the
original values, because a report full of PHI would defeat the purpose.

Setup: run ./setup.sh once (see README.md).

Usage:
  ./redact input.pdf output.pdf
  ./redact input.pdf output.pdf --flatten --report report.json
  ./redact input.pdf output.pdf --deny-list names.txt --ocr all
  ./redact input.pdf --dry-run      # detect only, no output

No automated de-identification is perfect. Always review the output before
releasing it, especially free-text clinical notes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass, field

import pymupdf

try:
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
except ImportError:  # pragma: no cover
    sys.exit("Missing dependency: pip install presidio-analyzer && python -m spacy download en_core_web_lg")

try:
    import pytesseract
    from PIL import Image
    HAVE_OCR = True
except ImportError:  # pragma: no cover
    HAVE_OCR = False


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Presidio entity types to redact. Covers the HIPAA Safe Harbor identifiers that
# can be found in text. Trim this list if you are over-redacting.
DEFAULT_ENTITIES = [
    "PERSON", "LOCATION", "DATE_TIME", "PHONE_NUMBER", "EMAIL_ADDRESS",
    "US_SSN", "US_DRIVER_LICENSE", "US_PASSPORT", "US_BANK_NUMBER", "US_ITIN",
    "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS", "URL", "MEDICAL_LICENSE",
    # custom recognizers added below
    "US_ZIP", "STREET_ADDRESS", "MRN", "NPI", "DOD_EDIPI",
]

# Labels whose value (rest of the line) is always redacted. Case-insensitive.
FIELD_LABELS = [
    r"patient(?:\s+name)?", r"name", r"pt\.?\s*name", r"guarantor", r"subscriber",
    r"insured", r"emergency\s+contact", r"next\s+of\s+kin", r"spouse", r"mother",
    r"father", r"parent(?:/guardian)?", r"guardian",
    r"d\.?o\.?b\.?", r"date\s+of\s+birth", r"birth\s*date",
    r"date\s+of\s+death", r"admit(?:ted|\s+date)?", r"discharge(?:d|\s+date)?",
    r"date\s+of\s+service", r"dos", r"visit\s+date", r"encounter\s+date",
    r"mrn", r"medical\s+record(?:\s+(?:number|no\.?|#))?", r"chart\s*(?:#|no\.?|number)",
    r"account(?:\s+(?:number|no\.?|#))?", r"acct\.?(?:\s*#)?", r"encounter\s*(?:#|id|number)",
    r"member\s*(?:id|#|number)", r"subscriber\s*(?:id|#)", r"policy\s*(?:#|no\.?|number)?",
    r"group\s*(?:#|no\.?|number)", r"insurance\s*(?:id|#)", r"health\s+plan\s*(?:id|#)?",
    r"medicaid\s*(?:id|#)?", r"medicare\s*(?:id|#)?", r"mbi",
    r"ssn", r"social\s+security(?:\s+(?:number|no\.?|#))?",
    r"driver'?s?\s+licen[cs]e(?:\s*#)?", r"dl\s*#", r"license\s*(?:#|no\.?|number)",
    r"npi", r"dea(?:\s*#)?", r"device\s+(?:id|serial)", r"serial\s*(?:#|no\.?|number)",
    r"address", r"addr\.?", r"street", r"city", r"zip(?:\s*code)?", r"postal\s+code",
    r"phone", r"tel(?:ephone)?", r"cell", r"mobile", r"home\s+phone", r"work\s+phone",
    r"fax", r"e-?mail", r"employer", r"vin", r"license\s+plate", r"ip(?:\s+address)?",
    # DoD / VA identifiers
    r"edipi", r"dod\s*id(?:\s*(?:#|no\.?|number))?", r"dod\s+benefits?\s*(?:#|no\.?|number)?",
    r"cac(?:\s*(?:#|id|no\.?|number))?", r"dbids(?:\s*id)?", r"deers(?:\s*id)?",
    r"military\s+id", r"sponsor(?:\s*(?:ssn|id|name|#))?", r"fmp", r"service\s+number",
    r"va\s+(?:file|claim)\s*(?:#|no\.?|number)?", r"c-?file(?:\s*(?:#|no\.?|number))?",
    r"claim\s*(?:#|no\.?|number)",
]

# DoD/VA numbers often appear without a colon ("EDIPI 1029384756", "his EDIPI is
# 1748291053"). Catch the digits after these keywords regardless of punctuation.
DOD_ID_RE = re.compile(
    r"\b(?:edipi|dod\s*id|dod\s+benefits?(?:\s+(?:number|no\.?|#))?|cac|dbids|deers(?:\s*id)?|"
    r"military\s+id|sponsor(?:\s+(?:ssn|id))?|va\s+(?:file|claim)|c-?file|claim)"
    r"(?:\s+(?:is|number|no\.?|#|id|was))*\s*[:#]?\s*(?P<value>\d[\d -]{6,14}\d)\b",
    re.IGNORECASE,
)
# A label must start the line or follow whitespace/punctuation and end in ':' or '#'.
LABEL_RE = re.compile(
    r"(?:^|(?<=[\s|,;(]))(?:" + "|".join(FIELD_LABELS) + r")\s*(?:[:#]|-\s)\s*(?P<value>[^\n|]+)",
    re.IGNORECASE,
)

OCR_DPI = 300
PAD = 1.0      # vertical padding (points) for boxes over real text
OCR_PAD = 2.0  # padding on all sides for boxes over scanned images

# Ages under 90 are not Safe Harbor identifiers, so "64 year old" is kept.
AGE_RE = re.compile(r"^\s*(\d{1,3})[\s-]*(?:y/?o|yo|years?[\s-]*old|year-old|yrs?)\s*$", re.I)


# --------------------------------------------------------------------------- #
# Detection engine
# --------------------------------------------------------------------------- #

def build_analyzer() -> AnalyzerEngine:
    analyzer = AnalyzerEngine()
    reg = analyzer.registry
    reg.add_recognizer(PatternRecognizer(
        supported_entity="US_ZIP",
        patterns=[Pattern("zip", r"\b\d{5}(?:-\d{4})?\b", 0.3)],
        context=["zip", "zipcode", "postal", "address", "city", "state"],
    ))
    reg.add_recognizer(PatternRecognizer(
        supported_entity="STREET_ADDRESS",
        patterns=[Pattern(
            "street",
            r"\b\d{1,6}\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z0-9]+\s+){1,4}"
            r"(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|"
            r"Way|Pl|Place|Pkwy|Parkway|Cir|Circle|Ter|Terrace|Hwy|Highway)\b\.?"
            r"(?:\s*(?:Apt|Unit|Suite|Ste|#)\.?\s*[A-Za-z0-9-]+)?",
            0.7,
        )],
    ))
    reg.add_recognizer(PatternRecognizer(
        supported_entity="MRN",
        patterns=[Pattern("mrn", r"\b[A-Z]{0,3}\d{6,10}\b", 0.2)],
        context=["mrn", "medical record", "chart", "account", "acct", "member", "patient id"],
    ))
    # EDIPI / DoD ID is 10 digits; the DoD Benefits Number is 11. Low base score,
    # boosted by nearby context words, so random 10-digit numbers are not hit.
    reg.add_recognizer(PatternRecognizer(
        supported_entity="DOD_EDIPI",
        patterns=[Pattern("edipi", r"\b\d{10,11}\b", 0.3)],
        context=["edipi", "dod", "cac", "dbids", "deers", "military", "sponsor",
                 "tricare", "benefits", "common access card", "id"],
    ))
    reg.add_recognizer(PatternRecognizer(
        supported_entity="NPI",
        patterns=[Pattern("npi", r"\b\d{10}\b", 0.2)],
        context=["npi", "provider", "national provider"],
    ))
    return analyzer


# --------------------------------------------------------------------------- #
# Page text model: words with boxes, joined into one string with char offsets
# --------------------------------------------------------------------------- #

@dataclass
class Word:
    text: str
    rect: pymupdf.Rect
    start: int = 0
    end: int = 0


@dataclass
class PageText:
    words: list[Word] = field(default_factory=list)
    text: str = ""

    @classmethod
    def build(cls, words_by_line: list[list[Word]]) -> "PageText":
        pt = cls()
        parts: list[str] = []
        pos = 0
        for line in words_by_line:
            for i, w in enumerate(line):
                if i:
                    parts.append(" ")
                    pos += 1
                w.start, w.end = pos, pos + len(w.text)
                parts.append(w.text)
                pos = w.end
                pt.words.append(w)
            parts.append("\n")
            pos += 1
        pt.text = "".join(parts)
        return pt

    def rects_for_span(self, start: int, end: int) -> list[pymupdf.Rect]:
        """Boxes covering a character span, merged into one box per line so the
        spaces between redacted words are covered too."""
        out: list[pymupdf.Rect] = []
        for w in self.words:
            if w.start < end and w.end > start:
                if out and abs(out[-1].y0 - w.rect.y0) < 2 and abs(out[-1].y1 - w.rect.y1) < 2:
                    out[-1] |= w.rect
                else:
                    out.append(pymupdf.Rect(w.rect))
        return out


def native_text(page: pymupdf.Page) -> PageText:
    lines: dict[tuple[int, int], list[Word]] = {}
    for x0, y0, x1, y1, txt, block, line, _ in page.get_text("words", sort=True):
        lines.setdefault((block, line), []).append(Word(txt, pymupdf.Rect(x0, y0, x1, y1)))
    return PageText.build(list(lines.values()))


def ocr_text(page: pymupdf.Page) -> PageText:
    if not HAVE_OCR:
        return PageText()
    pix = page.get_pixmap(dpi=OCR_DPI)
    img = Image.frombytes("RGB" if pix.n < 4 else "RGBA", (pix.width, pix.height), pix.samples)
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    scale = 72.0 / OCR_DPI
    derot = page.derotation_matrix
    lines: dict[tuple[int, int, int], list[Word]] = {}
    for i, txt in enumerate(data["text"]):
        if not txt.strip():
            continue
        x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
        r = pymupdf.Rect(x * scale, y * scale, (x + w) * scale, (y + h) * scale) * derot
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        lines.setdefault(key, []).append(Word(txt.strip(), r))
    return PageText.build(list(lines.values()))


def looks_scanned(page: pymupdf.Page) -> bool:
    if len(page.get_text().strip()) < 25:
        return bool(page.get_images())
    area = abs(page.rect)
    covered = 0.0
    for img in page.get_image_info():
        covered += abs(pymupdf.Rect(img["bbox"]) & page.rect)
    return area > 0 and covered / area > 0.5


# --------------------------------------------------------------------------- #
# Detection over a PageText
# --------------------------------------------------------------------------- #

@dataclass
class Hit:
    entity: str
    start: int
    end: int
    value: str


def detect(pt: PageText, analyzer: AnalyzerEngine, entities: list[str],
           threshold: float, deny: list[str], allow: set[str]) -> list[Hit]:
    hits: list[Hit] = []
    text = pt.text
    if not text.strip():
        return hits

    for r in analyzer.analyze(text=text, language="en", entities=entities, score_threshold=threshold):
        val = text[r.start:r.end]
        if val.strip().lower() in allow:
            continue
        age = AGE_RE.match(val)
        if r.entity_type == "DATE_TIME" and age and int(age.group(1)) < 90:
            continue
        hits.append(Hit(r.entity_type, r.start, r.end, val))

    for m in LABEL_RE.finditer(text):
        v0, v1 = m.span("value")
        val = text[v0:v1].rstrip()
        if len(val.strip()) >= 2:
            hits.append(Hit("LABELED_FIELD", v0, v0 + len(val), val))

    for m in DOD_ID_RE.finditer(text):
        v0, v1 = m.span("value")
        hits.append(Hit("DOD_ID", v0, v1, text[v0:v1]))

    for term in deny:
        for m in re.finditer(re.escape(term), text, re.IGNORECASE):
            hits.append(Hit("DENY_LIST", m.start(), m.end(), m.group()))
    return hits


# --------------------------------------------------------------------------- #
# Main redaction pass
# --------------------------------------------------------------------------- #

def redact(args: argparse.Namespace) -> int:
    analyzer = build_analyzer()
    entities = args.entities or DEFAULT_ENTITIES
    deny = [t.strip() for t in open(args.deny_list) if t.strip()] if args.deny_list else []
    allow = {t.strip().lower() for t in open(args.allow_list) if t.strip()} if args.allow_list else set()

    doc = pymupdf.open(args.input)
    if doc.needs_pass:
        sys.exit("PDF is password protected. Decrypt it first.")
    # Fail closed: without OCR, text inside scanned images would pass through untouched.
    if args.ocr != "off":
        if not HAVE_OCR:
            sys.exit("OCR is required but pytesseract/Pillow is missing: python -m pip install pytesseract")
        try:
            pytesseract.get_tesseract_version()
        except Exception:
            sys.exit("OCR is required but the Tesseract program is not installed or not on PATH.\n"
                     "  macOS: brew install tesseract\n"
                     "Use --ocr off only if you are sure the PDF has no scanned pages.")

    # Turn form fields and annotations into page content so their values are scanned.
    try:
        doc.bake(annots=True, widgets=True)
    except Exception as e:  # older PyMuPDF
        print(f"warning: could not bake forms/annotations ({e}); they will be removed by scrub", file=sys.stderr)

    report = {"input": args.input, "pages": [], "totals": Counter()}
    secret_values: set[str] = set()  # kept in memory only, for verification

    for page in doc:
        sources: list[tuple[str, PageText]] = [("text", native_text(page))]
        do_ocr = args.ocr == "all" or (args.ocr == "auto" and looks_scanned(page))
        if do_ocr and HAVE_OCR:
            sources.append(("ocr", ocr_text(page)))

        counts: Counter = Counter()
        for src, pt in sources:
            # Text glyphs are removed whole if touched, so native boxes need no side
            # padding. OCR boxes are approximate pixels, so pad them generously.
            pad = (0, PAD) if src == "text" else (OCR_PAD, OCR_PAD)
            for h in detect(pt, analyzer, entities, args.threshold, deny, allow):
                counts[h.entity] += 1
                secret_values.add(h.value.strip())
                for r in pt.rects_for_span(h.start, h.end):
                    if not args.dry_run:
                        page.add_redact_annot(r + (-pad[0], -pad[1], pad[0], pad[1]), fill=(0, 0, 0))

        if not args.dry_run:
            page.apply_redactions(
                images=pymupdf.PDF_REDACT_IMAGE_PIXELS,      # blank pixels under boxes
                graphics=getattr(pymupdf, "PDF_REDACT_LINE_ART_REMOVE_IF_COVERED", 1),
                text=getattr(pymupdf, "PDF_REDACT_TEXT_REMOVE", 0),  # delete overlapping glyphs
            )
        report["pages"].append({"page": page.number + 1, "ocr": do_ocr, "found": dict(counts)})
        report["totals"].update(counts)
        print(f"page {page.number + 1}: {sum(counts.values())} item(s)"
              f"{' [ocr]' if do_ocr else ''} {dict(counts) or ''}")

    report["totals"] = dict(report["totals"])
    if args.dry_run:
        print(json.dumps(report["totals"], indent=2))
        return 0

    # Strip everything that is not page content.
    doc.scrub(
        attached_files=True, embedded_files=True, metadata=True, xml_metadata=True,
        javascript=True, remove_links=True, thumbnails=True, reset_fields=True,
        reset_responses=True, hidden_text=True, clean_pages=True, redactions=False,
    )
    doc.set_toc([])
    doc.set_metadata({})

    if args.flatten:
        flat = pymupdf.open()
        for page in doc:
            pix = page.get_pixmap(dpi=args.dpi)
            newp = flat.new_page(width=page.rect.width, height=page.rect.height)
            newp.insert_image(newp.rect, pixmap=pix)
        doc.close()
        doc = flat
        doc.set_metadata({})

    doc.save(args.output, garbage=4, deflate=True, clean=True, no_new_id=False)
    doc.close()
    print(f"wrote {args.output} (not final until verification passes)")

    leaks = verify(args.output, analyzer, entities, args.threshold, secret_values, allow,
                   args.ocr, args.show_residual)
    report["verification"] = leaks
    if args.report:
        with open(args.report, "w") as f:
            json.dump(report, f, indent=2)
        print(f"report: {args.report}")
    return 2 if leaks["leaked_values"] else 0


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #

def verify(path: str, analyzer: AnalyzerEngine, entities: list[str], threshold: float,
           secrets: set[str], allow: set[str], ocr_mode: str, show_residual: bool = False) -> dict:
    doc = pymupdf.open(path)
    n = doc.page_count
    # A value counts as leaked if it reappears verbatim (ignore very short tokens,
    # which collide with ordinary words).
    checks = {s for s in secrets if len(s) >= 4}
    leaked: set[str] = set()
    residual_hits = []
    for page in doc:
        # Re-reading and re-OCRing every page is slow on big scans, so show progress.
        print(f"\rverifying page {page.number + 1}/{n} ...", end="", file=sys.stderr, flush=True)
        text = page.get_text()
        if HAVE_OCR and ocr_mode != "off" and (ocr_mode == "all" or looks_scanned(page)):
            text += "\n" + ocr_text(page).text
        leaked |= {s for s in checks if s in text}
        for r in analyzer.analyze(text=text, language="en", entities=entities,
                                  score_threshold=max(threshold, 0.6)):
            val = text[r.start:r.end].strip()
            age = AGE_RE.match(val)
            if val.lower() in allow or (r.entity_type == "DATE_TIME" and age and int(age.group(1)) < 90):
                continue
            residual_hits.append((r.entity_type, val))
    print(file=sys.stderr)
    meta = {k: v for k, v in (doc.metadata or {}).items() if v and k not in ("format", "encryption")}
    xmp = doc.get_xml_metadata()
    embedded = doc.embfile_count()
    doc.close()
    leaked = sorted(leaked)
    residual = Counter(e for e, _ in residual_hits)
    if show_residual and residual_hits:
        # Console only, never written to the report. These are things to eyeball:
        # usually OCR noise from the black boxes or words the model misread.
        for e, v in residual_hits:
            print(f"  residual {e}: {v!r}")
    result = {
        "leaked_values": len(leaked),
        "residual_detections": dict(residual),
        "metadata_left": list(meta.keys()),
        "xmp_left": bool(xmp),
        "embedded_files_left": embedded,
    }
    status = "PASS" if not leaked and not meta and not xmp and not embedded else "CHECK"
    print(f"verify: {status} | leaked values: {len(leaked)} | residual high-confidence "
          f"detections: {dict(residual) or 'none'} | metadata: {list(meta) or 'clean'}")
    if leaked:
        print("  LEAK: some redacted values are still extractable. Re-run with --flatten.", file=sys.stderr)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="Detect and truly remove PHI/PII from a PDF.")
    ap.add_argument("input")
    ap.add_argument("output", nargs="?")
    ap.add_argument("--ocr", choices=["auto", "all", "off"], default="auto",
                    help="auto: OCR pages that look scanned (default); all: OCR every page")
    ap.add_argument("--flatten", action="store_true",
                    help="rasterize every page after redaction so no text layer survives")
    ap.add_argument("--dpi", type=int, default=200, help="DPI for --flatten (default 200)")
    ap.add_argument("--threshold", type=float, default=0.4, help="Presidio score threshold (default 0.4)")
    ap.add_argument("--entities", nargs="+", help="override entity types to redact")
    ap.add_argument("--deny-list", help="file with one term per line to always redact")
    ap.add_argument("--allow-list", help="file with one term per line to never redact")
    ap.add_argument("--report", help="write a JSON summary (types and counts only, no values)")
    ap.add_argument("--dry-run", action="store_true", help="detect and report only, write nothing")
    ap.add_argument("--show-residual", action="store_true",
                    help="print residual detections in the output to the console for review")
    args = ap.parse_args()
    if not args.dry_run and not args.output:
        ap.error("output path is required unless --dry-run")
    sys.exit(redact(args))


if __name__ == "__main__":
    main()
