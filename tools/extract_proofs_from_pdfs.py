#!/usr/bin/env python3
import re, os, json, csv, hashlib, mimetypes, pathlib, sys
from typing import Optional, Tuple, Dict

# Dépendance: pip install PyPDF2
from PyPDF2 import PdfReader

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
PROOFS = ROOT / "proofs"
BY_DOC = PROOFS / "by-doc"
INDEX = PROOFS / "index.jsonl"
MAPPING = PROOFS / "mapping.csv"

# Regex (tolérantes)
RE_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
RE_HEX64 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
RE_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def extract_footer_text(pdf_path: pathlib.Path, max_pages_scan: int = 3) -> str:
    """Concat du texte des dernières pages (jusqu'à max_pages_scan) pour capter le pied de page."""
    reader = PdfReader(str(pdf_path))
    n = len(reader.pages)
    text_parts = []
    for i in range(max(n - max_pages_scan, 0), n):
        try:
            text_parts.append(reader.pages[i].extract_text() or "")
        except Exception:
            pass
    return "\n".join(text_parts)

def parse_proof(text: str) -> Dict[str, Optional[str]]:
    # 1) On récupère toutes les suites hex 64 — on supposera que
    # la première est SHA256 et la deuxième (différente) est le TXID.
    hexes = RE_HEX64.findall(text)
    sha256 = None
    txid = None
    if hexes:
        sha256 = hexes[0].lower()
        # cherche une autre 64-hex distincte pour le TXID
        for h in hexes[1:]:
            if h.lower() != sha256:
                txid = h.lower()
                break

    woleet = None
    m_uuid = RE_UUID.search(text)
    if m_uuid:
        woleet = m_uuid.group(0).lower()

    anchored_utc = None
    m_iso = RE_ISO.search(text)
    if m_iso:
        anchored_utc = m_iso.group(0)

    return {
        "sha256": sha256,
        "bitcoin_txid": txid,
        "woleet_proof_id": woleet,
        "anchored_utc": anchored_utc
    }

def slugify(name: str) -> str:
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s

def main():
    PROOFS.mkdir(exist_ok=True)
    BY_DOC.mkdir(parents=True, exist_ok=True)

    rows = []
    index_lines = []

    pdfs = sorted(DOCS.rglob("*.pdf"))
    if not pdfs:
        print(f"[INFO] Aucun PDF trouvé sous {DOCS}")
        sys.exit(0)

    for pdf in pdfs:
        rel = pdf.relative_to(ROOT)
        print(f"→ Analyse {rel}")
        text = extract_footer_text(pdf)
        proof = parse_proof(text)

        # Métadonnées fichier
        size_bytes = pdf.stat().st_size
        mimetype = mimetypes.guess_type(pdf.name)[0] or "application/pdf"
        calc_sha = sha256_file(pdf)

        # Si le SHA256 extrait du pied de page ne matche pas le SHA256 recalculé, on garde les deux.
        sha_from_footer = proof.get("sha256")
        if sha_from_footer and sha_from_footer != calc_sha:
            print(f"[WARN] SHA256 du footer ≠ SHA256 calculé pour {rel}")

        # Slug basé sur le nom du fichier
        base = pdf.stem  # sans extension
        slug = slugify(base)

        # Écrit proof.json
        pdir = BY_DOC / slug
        pdir.mkdir(parents=True, exist_ok=True)
        pjson = pdir / "proof.json"
        with pjson.open("w", encoding="utf-8") as out:
            json.dump({
                "schema_version": "1.0",
                "document": {
                    "title": base,
                    "slug": slug,
                    "filename": str(rel).replace("\\","/"),
                    "mimetype": mimetype,
                    "size_bytes": size_bytes,
                    "sha256": calc_sha,  # vérité de référence = fichier publié
                    "canonical_uri": None,
                    "version": None
                },
                "authorship": {
                    "author": "Caroline Caldwell – GaiaSentinel",
                    "copyright": "© 2025 Caroline Caldwell – GaiaSentinel",
                    "license": "CC BY-NC-ND 4.0 International"
                },
                "anchoring": {
                    "anchor_network": "bitcoin-mainnet",
                    "txid": proof.get("bitcoin_txid"),
                    "block_height": None,
                    "block_time_utc": proof.get("anchored_utc"),
                    "op_return": None
                },
                "woleet": {
                    "proof_id": proof.get("woleet_proof_id"),
                    "link": None
                },
                "dates": {
                    "created_utc": None,
                    "anchored_utc": proof.get("anchored_utc"),
                    "published_utc": None
                },
                "notes": "Preuve extraite automatiquement depuis le pied de page du PDF."
            }, out, ensure_ascii=False, indent=2)

        # checksums.txt
        with (pdir / "checksums.txt").open("w", encoding="utf-8") as cs:
            cs.write(f"SHA256  {calc_sha}  {rel}\n")

        # mapping.csv (ligne)
        rows.append({
            "slug": slug,
            "filename": str(rel).replace("\\","/"),
            "sha256": calc_sha,
            "bitcoin_txid": proof.get("bitcoin_txid"),
            "woleet_proof_id": proof.get("woleet_proof_id"),
            "anchored_utc": proof.get("anchored_utc"),
            "canonical_uri": "",
            "title": base,
            "version": "",
            "mimetype": mimetype,
            "size_bytes": size_bytes
        })

        # index.jsonl (ligne)
        index_lines.append({
            "slug": slug,
            "filename": str(rel).replace("\\","/"),
            "sha256": calc_sha,
            "bitcoin_txid": proof.get("bitcoin_txid"),
            "woleet_proof_id": proof.get("woleet_proof_id"),
            "anchored_utc": proof.get("anchored_utc")
        })

    # Écrit mapping.csv
    headers = ["slug","filename","sha256","bitcoin_txid","woleet_proof_id","anchored_utc","canonical_uri","title","version","mimetype","size_bytes"]
    with MAPPING.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # Écrit index.jsonl
    with INDEX.open("w", encoding="utf-8") as f:
        for line in index_lines:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")

    print(f"[OK] {len(rows)} PDF traités.")
    print(f"[OK] mapping.csv : {MAPPING}")
    print(f"[OK] index.jsonl : {INDEX}")
    print(f"[OK] proofs/by-doc/*/proof.json générés.")

if __name__ == "__main__":
    main()

