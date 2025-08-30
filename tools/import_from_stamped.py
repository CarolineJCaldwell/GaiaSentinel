#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
import_from_stamped.py
Consolide les preuves horodatées à partir de 'stamped/' et génère une structure normalisée dans 'proofs/'.

Points clés :
- Multi-versions par dossier
- Reçus JSON : n'importe quel *.json (même nom que le PDF), pas besoin que "woleet" figure dans le nom
- Appariement par NOM d'abord (même base), puis vérification par HASH si targetHash présent
- Génère proofs/by-doc/<slug_version>/{proof.json, checksums.txt, woleet_receipt.json, woleet_receipt.pdf, screenshot}
- Construit/écrase proofs/mapping.csv et proofs/index.jsonl

Options :
  --symlink    : liens symboliques pour annexes
  --dry-run    : simulation
  --verbose    : logs détaillés
  --root PATH  : racine du dépôt

Usage :
  python3 tools/import_from_stamped.py
  python3 tools/import_from_stamped.py --symlink --verbose
"""

import argparse
import csv
import hashlib
import json
import mimetypes
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HEX64 = re.compile(r"^[a-f0-9]{64}$", re.I)

def log(msg: str, *, verbose: bool = True):
    if verbose:
        print(msg)

def warn(msg: str):
    print(f"[WARN] {msg}")

def err(msg: str):
    print(f"[ERR]  {msg}", file=sys.stderr)

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def slugify(s: str) -> str:
    s = s.lower()
    s = s.translate(str.maketrans("àâäéèêëïîôöùûüç", "aaaeeeeiioouuuc"))
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s

def parse_version_from_name(name: str) -> Optional[str]:
    m = re.search(r"(?:^|[_\-\s])(v\d+(?:\.\d+)*)", name, flags=re.I)
    if not m:
        return None
    return m.group(1).lower().replace(".", "-")

def norm_iso(dt_like) -> Optional[str]:
    if not dt_like:
        return None
    try:
        dt = datetime.fromisoformat(str(dt_like).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

def ensure_dir(p: Path, dry: bool):
    if dry:
        return
    p.mkdir(parents=True, exist_ok=True)

def copy_or_link(src: Path, dst: Path, symlink: bool, dry: bool, verbose: bool):
    if dry:
        log(f"[DRY] {'ln -s' if symlink else 'cp'} {src} -> {dst}", verbose=verbose)
        return
    if dst.exists():
        return
    if symlink:
        try:
            os.symlink(os.path.relpath(src, start=dst.parent), dst)
        except FileExistsError:
            pass
    else:
        shutil.copy2(src, dst)

# ----------- Woleet parsing (souple) -----------

def parse_woleet_receipt(data: Dict) -> Dict[str, Optional[str]]:
    """
    Tente d'extraire les champs essentiels depuis un JSON de reçu Woleet.
    Retourne : proof_id, sha256(targetHash), txid, block_height, anchored_utc, link
    """
    proof_id = data.get("id") or data.get("proof_id") or data.get("proofId")
    target_hash = (data.get("targetHash") or data.get("hash") or "") or None
    if target_hash:
        target_hash = target_hash.lower()

    anchors = data.get("anchors") or data.get("anchor") or []
    if isinstance(anchors, dict):
        anchors = [anchors]

    txid = None
    block_height = None
    block_time = None

    for a in anchors:
        atype = str(a.get("type", "")).lower()
        if atype in ("btc", "bitcoin", "opreturn", "op-return", "op_return"):
            txid = a.get("txId") or a.get("txid") or txid
            block_height = a.get("blockHeight") or block_height
            block_time = a.get("time") or a.get("timestamp") or a.get("confirmedAt") or block_time

    txid = txid or data.get("txid") or data.get("txId") or None
    if txid:
        txid = txid.lower()

    anchored_utc = (
        norm_iso(block_time)
        or norm_iso(data.get("blockTime"))
        or norm_iso(data.get("anchoredOn"))
        or norm_iso(data.get("created"))
    )
    link = data.get("receiptUrl") or data.get("url") or None

    return {
        "proof_id": proof_id,
        "sha256": target_hash,
        "txid": txid,
        "block_height": block_height,
        "anchored_utc": anchored_utc,
        "link": link
    }

# ----------- Collecte par dossier -----------

def base_of(stem: str) -> str:
    """Supprime suffixes usuels pour comparer les bases de nom."""
    s = re.sub(r"(?i)(?:_)?(attestation|receipt)$", "", stem)
    return s

def collect_folder(folder: Path, verbose: bool):
    """
    Renvoie :
      folder_label, base_slug,
      jsons: liste[Path],
      pdf_canons: liste[Path] (hors attestation/receipt),
      attestations: liste[Path] (attestation ou receipt.pdf),
      screenshots: liste[Path]
    """
    folder_label = folder.name
    base_slug = slugify(re.sub(r"(?:^|[_\-\s])v\d+(?:\.\d+)*$", "", folder_label, flags=re.I))
    log(f"→ {folder_label}  =>  base={base_slug}", verbose=verbose)

    jsons: List[Path] = []
    pdf_canons: List[Path] = []
    attestations: List[Path] = []
    screenshots: List[Path] = []

    for f in sorted(folder.iterdir()):
        low = f.name.lower()
        if f.suffix.lower() == ".json":
            jsons.append(f)  # PREND TOUS LES JSON
        elif f.suffix.lower() == ".pdf" and ("receipt" in low or "attestation" in low):
            attestations.append(f)
        elif f.suffix.lower() == ".pdf":
            pdf_canons.append(f)
        elif f.suffix.lower() in (".png", ".jpg", ".jpeg") and ("woleet" in low or "receipt" in low or "attestation" in low):
            screenshots.append(f)

    return folder_label, base_slug, jsons, pdf_canons, attestations, screenshots

def pick_attestation_for(pdf: Path, attestations: List[Path]) -> Optional[Path]:
    pref = re.sub(r"\.pdf$", "", pdf.name, flags=re.I).lower()
    for a in attestations:
        low = a.name.lower()
        if pref in low or "attestation" in low or "receipt" in low:
            return a
    return None

def build_slug_version(base_slug: str, pdf_name: str, folder_label: str, anchored_utc: Optional[str]) -> str:
    """
    Détermine la version :
      - Priorité: version trouvée dans le nom du PDF
      - Sinon: version dans le nom du dossier
      - Sinon: **défaut = v1-0** (au lieu de v-unknown)
    """
    version = parse_version_from_name(pdf_name) or parse_version_from_name(folder_label)
    if not version:
        version = "v1-0"  # <— DEMANDÉ : version par défaut 1.0
    return f"{base_slug}_{version}"

def write_proof_set(
    outdir: Path,
    proof_json: Dict,
    pdf_path: Path,
    receipt_json_path: Path,
    attestation_pdf: Optional[Path],
    screenshots: List[Path],
    *,
    symlink: bool,
    dry: bool,
    verbose: bool
):
    ensure_dir(outdir, dry)
    # proof.json
    if dry:
        log(f"[DRY] write {outdir/'proof.json'}", verbose=verbose)
    else:
        (outdir / "proof.json").write_text(json.dumps(proof_json, ensure_ascii=False, indent=2), encoding="utf-8")

    # checksums.txt
    if dry:
        log(f"[DRY] write {outdir/'checksums.txt'}", verbose=verbose)
    else:
        with (outdir / "checksums.txt").open("w", encoding="utf-8") as cs:
            rel = pdf_path
            try:
                rel = pdf_path.relative_to(outdir.parents[2])  # racine dépôt
            except Exception:
                pass
            rel_str = str(rel).replace("\\", "/")
            sha = proof_json['document']['sha256']
            cs.write(f"SHA256  {sha}  {rel_str}\n")

    # annexes
    copy_or_link(receipt_json_path, outdir / "woleet_receipt.json", symlink, dry, verbose)
    if attestation_pdf:
        copy_or_link(attestation_pdf, outdir / "woleet_receipt.pdf", symlink, dry, verbose)
    if screenshots:
        copy_or_link(screenshots[0], outdir / screenshots[0].name, symlink, dry, verbose)

# ----------- Main -----------

def main():
    ap = argparse.ArgumentParser(description="Importe les preuves (JSON+PDF) depuis 'stamped/' vers 'proofs/'.")
    ap.add_argument("--root", type=str, default=None, help="Chemin racine du dépôt (par défaut : parent du script)")
    ap.add_argument("--symlink", action="store_true", help="Créer des liens symboliques pour les annexes")
    ap.add_argument("--dry-run", action="store_true", help="Simulation sans écriture")
    ap.add_argument("--verbose", action="store_true", help="Logs détaillés")
    args = ap.parse_args()

    script_path = Path(__file__).resolve()
    ROOT = Path(args.root).resolve() if args.root else script_path.parents[1]
    STAMPED = ROOT / "stamped"
    PROOFS = ROOT / "proofs"
    BY_DOC = PROOFS / "by-doc"
    INDEX = PROOFS / "index.jsonl"
    MAPPING = PROOFS / "mapping.csv"

    log(f"[INFO] ROOT    = {ROOT}", verbose=True)
    log(f"[INFO] STAMPED = {STAMPED}", verbose=True)
    log(f"[INFO] PROOFS  = {PROOFS}", verbose=True)

    if not STAMPED.exists():
        err(f"Dossier manquant : {STAMPED}"); sys.exit(1)

    ensure_dir(PROOFS, args.dry_run)
    ensure_dir(BY_DOC, args.dry_run)

    rows: List[Dict] = []
    index_lines: List[Dict] = []

    subdirs = [p for p in STAMPED.iterdir() if p.is_dir()]
    if not subdirs:
        warn("Aucun sous-dossier dans 'stamped/'.")
    for d in sorted(subdirs, key=lambda p: p.name.lower()):
        folder_label, base_slug, jsons, pdf_canons, attestations, screenshots = collect_folder(d, args.verbose)

        if not jsons:
            warn(f"Aucun reçu JSON dans {d} (attendu : un .json par version)")
            continue
        if not pdf_canons:
            warn(f"Aucun PDF canon détecté dans {d} (hors attestation/receipt)")
            continue

        # index SHA256 de tous les PDF canons
        pdf_index: Dict[str, Path] = {}
        for pdf in pdf_canons:
            try:
                pdf_index[sha256_file(pdf)] = pdf
            except Exception as e:
                warn(f"Impossible de hasher {pdf}: {e}")

        # dictionnaire des pdf par base de nom (pour matching par nom)
        pdf_by_base: Dict[str, List[Path]] = {}
        for pdf in pdf_canons:
            b = base_of(pdf.stem).lower()
            pdf_by_base.setdefault(b, []).append(pdf)

        # pour chaque JSON (= reçu)
        for jpath in jsons:
            try:
                jdata = json.loads(jpath.read_text(encoding="utf-8"))
            except Exception as e:
                warn(f"JSON illisible: {jpath} ({e})")
                continue

            info = parse_woleet_receipt(jdata)
            target = info["sha256"]  # peut être None si pas présent

            # 1) matching PAR NOM d'abord
            base_json = base_of(jpath.stem).lower()
            candidates = pdf_by_base.get(base_json, [])

            pdf_match: Optional[Path] = None

            if candidates:
                # s'il y a un seul candidat, on le prend ;
                # s'il y en a plusieurs, on affine par hash si possible
                if len(candidates) == 1:
                    pdf_match = candidates[0]
                else:
                    if target and HEX64.match(target):
                        for c in candidates:
                            if sha256_file(c).lower() == target:
                                pdf_match = c
                                break
                    if pdf_match is None:
                        pdf_match = sorted(candidates, key=lambda p: (p.stat().st_mtime, p.name))[0]
            else:
                # 2) matching PAR HASH (si target disponible)
                if target and HEX64.match(target):
                    pdf_match = pdf_index.get(target)
                if pdf_match is None:
                    warn(f"Aucun PDF canon ne correspond au reçu {jpath.name} (base='{base_json}', hash={target[:12] if target else 'None'})")
                    continue

            # métadonnées du PDF retenu
            mimetype = mimetypes.guess_type(pdf_match.name)[0] or "application/pdf"
            size_bytes = pdf_match.stat().st_size
            calc_sha = sha256_file(pdf_match)

            # si target présent mais ≠ recalcul : alerte
            if target and HEX64.match(target) and calc_sha != target:
                warn(f"SHA256 PDF ≠ targetHash pour {pdf_match.name} (recalc={calc_sha[:12]} target={target[:12]})")

            # déterminer version + slug_version (avec défaut v1-0)
            slug_version = build_slug_version(base_slug, pdf_match.name, d.name, info["anchored_utc"])
            outdir = BY_DOC / slug_version

            att_pdf = pick_attestation_for(pdf_match, attestations)

            # chemin relatif propre
            try:
                rel_filename = str(pdf_match.relative_to(ROOT)).replace("\\", "/")
            except Exception:
                rel_filename = str(pdf_match)

            proof_json = {
                "schema_version": "1.0",
                "document": {
                    "title": folder_label,
                    "slug": base_slug,
                    "version": slug_version.split("_", 1)[1] if "_" in slug_version else "v1-0",
                    "filename": rel_filename,
                    "mimetype": mimetype,
                    "size_bytes": size_bytes,
                    "sha256": calc_sha,
                    "canonical_uri": None
                },
                "authorship": {
                    "author": "Caroline Caldwell – GaiaSentinel",
                    "copyright": "© 2025 Caroline Caldwell – GaiaSentinel",
                    "license": "CC BY-NC-ND 4.0 International"
                },
                "anchoring": {
                    "anchor_network": "bitcoin-mainnet",
                    "txid": info["txid"],
                    "block_height": info["block_height"],
                    "block_time_utc": info["anchored_utc"],
                    "op_return": None
                },
                "woleet": {
                    "proof_id": info["proof_id"],
                    "link": info["link"]
                },
                "dates": {
                    "created_utc": None,
                    "anchored_utc": info["anchored_utc"],
                    "published_utc": None
                },
                "notes": f"Import depuis stamped/ ; reçu = {jpath.name}"
            }

            # écrit l'ensemble
            write_proof_set(
                outdir=outdir,
                proof_json=proof_json,
                pdf_path=pdf_match,
                receipt_json_path=jpath,
                attestation_pdf=att_pdf,
                screenshots=screenshots,
                symlink=args.symlink,
                dry=args.dry_run,
                verbose=args.verbose
            )

            # lignes mapping & index
            rows.append({
                "slug": slug_version,
                "filename": rel_filename,
                "sha256": calc_sha,
                "bitcoin_txid": info["txid"] or "",
                "woleet_proof_id": info["proof_id"] or "",
                "anchored_utc": info["anchored_utc"] or "",
                "canonical_uri": "",
                "title": folder_label,
                "version": slug_version.split("_", 1)[1] if "_" in slug_version else "v1-0",
                "mimetype": mimetype,
                "size_bytes": size_bytes
            })
            index_lines.append({
                "slug": slug_version,
                "filename": rel_filename,
                "sha256": calc_sha,
                "bitcoin_txid": info["txid"] or "",
                "woleet_proof_id": info["proof_id"] or "",
                "anchored_utc": info["anchored_utc"] or ""
            })

    # écrit mapping et index
    if rows:
        headers = ["slug","filename","sha256","bitcoin_txid","woleet_proof_id","anchored_utc","canonical_uri","title","version","mimetype","size_bytes"]
        if not args.dry_run:
            with (PROOFS / "mapping.csv").open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=headers)
                w.writeheader()
                w.writerows(rows)
            with (PROOFS / "index.jsonl").open("w", encoding="utf-8") as f:
                for line in index_lines:
                    f.write(json.dumps(line, ensure_ascii=False) + "\n")
        log(f"[OK] Import terminé. {len(rows)} versions indexées.", verbose=True)
        log(f"[OK] Mapping : {MAPPING}", verbose=True)
        log(f"[OK] Index   : {INDEX}", verbose=True)
    else:
        warn("Aucune version indexée (vérifie la présence des .json et .pdf canons).")

if __name__ == "__main__":
    main()

