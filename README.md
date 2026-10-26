# redact-pdf

Local, offline PHI/PII redaction for PDFs, including scanned medical records.
Nothing leaves your machine.

It finds names, dates, SSNs, phone numbers, addresses, MRNs, insurance IDs and
DoD/VA identifiers (EDIPI/DoD ID, DoD Benefits Number, CAC, DBIDS, sponsor SSN,
VA file and claim numbers). The text is deleted, not just covered: scanned pages
are OCR'd and the pixels under each box are blanked. Metadata, attachments,
bookmarks and hidden text are stripped. When it's done, it re-reads the output
to verify that nothing it redacted is still there.

## Setup

Needs macOS or Linux, Python 3.10 to 3.13 and Homebrew (on macOS). The script
installs anything that's missing.

```bash
git clone https://github.com/<you>/redact-pdf.git
cd redact-pdf
./setup.sh --link
```

`setup.sh` does the following:

- Picks a supported Python.
- Installs Tesseract OCR.
- Builds a private `.venv`.
- Installs `requirements.txt`, including the spaCy model (about 500 MB the first time).
- Runs a smoke test on fake records.

`--link` adds a `redact` command you can run from any folder. If it says
`~/.local/bin` isn't on your PATH, add the line it prints to `~/.zshrc`.

Python 3.14 and newer are not supported yet, because spaCy and numpy can't be
built for them on macOS. `setup.sh` skips those versions automatically.

## Use

```bash
redact record.pdf record_redacted.pdf
redact record.pdf record_redacted.pdf --flatten              # no text layer left at all
redact record.pdf record_redacted.pdf --deny-list names.txt  # always remove these terms
redact record.pdf --dry-run                                  # show what it would find
```

| Option | What it does |
|---|---|
| `--flatten` | Turn every page into an image after redacting. Use this for anything you release. |
| `--deny-list FILE` | One term per line that is always redacted, such as name variants or a known EDIPI. |
| `--allow-list FILE` | One term per line that is never redacted, to cut down over-redaction. |
| `--ocr auto\|all\|off` | `auto` (the default) OCRs pages that look scanned. `all` OCRs every page. |
| `--report FILE` | Writes a JSON summary of entity types and counts per page. It never contains the values. |
| `--threshold N` | Detection confidence, 0 to 1 (default 0.4). Lower it to catch more. |
| `--show-residual` | Prints anything still suspicious after redaction, to the terminal only. |

Large scanned files take a while. A 136-page scan means 136 pages of OCR going
in, and again for verification. The output is not final until you see
`verify: PASS`. The script exits with status 2 if a redacted value survived.

## Updating

```bash
git pull
./setup.sh
```

## Limits

No automated de-identification is perfect. Free-text notes, unusual name
spellings, handwriting and poor scans are where it can miss things. It also
leans toward over-redacting. Review every output before you share it, and treat
a passing check as "nothing obvious leaked," not as a certified HIPAA Safe
Harbor de-identification.

## Keep records out of this repo

`.gitignore` blocks PDFs, images, reports and deny/allow lists so patient data
can't be committed by accident. Keep your records and outputs in a separate
folder. `git add -f` overrides the ignore rules, so don't use it here.

## Test

```bash
.venv/bin/python tests/smoke_test.py
```

The test builds fake records (a text page, a filled form, a scanned page and a
page of DoD identifiers), redacts them, and fails if any fake identifier
survives or the clinical text is lost.
