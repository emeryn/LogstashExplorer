import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("LSX_SECRETS_BACKEND", "env")
os.environ.setdefault("LSX_PKI_DIR", str(Path(__file__).parent / "_no_pki"))
