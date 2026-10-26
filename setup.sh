#!/usr/bin/env bash
# One-time setup for redact-pdf.
# Creates .venv with a supported Python, installs dependencies and the spaCy
# model, makes sure Tesseract is installed, then runs the smoke test.
#
#   ./setup.sh            normal setup
#   ./setup.sh --link     also put a `redact` command on your PATH (~/.local/bin)
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
LINK=0
[[ "${1:-}" == "--link" ]] && LINK=1

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
fail() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Pick a supported Python (newest first). 3.14+ lacks spaCy/numpy wheels.
PY=""
for v in 3.13 3.12 3.11 3.10; do
  if command -v "python$v" >/dev/null 2>&1; then PY="python$v"; break; fi
done
if [[ -z "$PY" ]]; then
  if command -v brew >/dev/null 2>&1; then
    say "No supported Python found, installing python@3.12 with Homebrew"
    brew install python@3.12
    PY="$(brew --prefix)/bin/python3.12"
  else
    fail "Need Python 3.10-3.13. Install one (macOS: brew install python@3.12) and rerun."
  fi
fi
say "Using $($PY --version) ($PY)"

# 2. Tesseract for OCR of scanned pages.
if ! command -v tesseract >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    say "Installing tesseract with Homebrew"
    brew install tesseract
  elif command -v apt-get >/dev/null 2>&1; then
    say "Installing tesseract with apt"
    sudo apt-get install -y tesseract-ocr
  else
    fail "Install Tesseract OCR (https://tesseract-ocr.github.io) and rerun."
  fi
fi
say "Tesseract: $(tesseract --version 2>&1 | head -1)"

# 3. Virtual environment and Python packages.
if [[ -d .venv ]] && ! .venv/bin/python -c 'import sys; sys.exit(not (3,10) <= sys.version_info[:2] < (3,14))' 2>/dev/null; then
  say "Existing .venv uses an unsupported Python, recreating it"
  rm -rf .venv
fi
[[ -d .venv ]] || { say "Creating .venv"; "$PY" -m venv .venv; }
say "Installing dependencies (first run downloads ~500 MB, mostly the spaCy model)"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

# 4. Optional: put `redact` on PATH.
chmod +x redact
if [[ $LINK -eq 1 ]]; then
  mkdir -p "$HOME/.local/bin"
  ln -sf "$ROOT/redact" "$HOME/.local/bin/redact"
  say "Linked $HOME/.local/bin/redact"
  case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *)
    echo "   Add this to ~/.zshrc so the command is found:"
    echo '   export PATH="$HOME/.local/bin:$PATH"' ;;
  esac
fi

# 5. Prove it works on fake data.
say "Running smoke test on synthetic records"
.venv/bin/python tests/smoke_test.py

say "Done. Usage:"
if [[ $LINK -eq 1 ]]; then
  echo "   redact input.pdf output.pdf"
else
  echo "   $ROOT/redact input.pdf output.pdf"
  echo "   (run ./setup.sh --link to use just 'redact' from any folder)"
fi
