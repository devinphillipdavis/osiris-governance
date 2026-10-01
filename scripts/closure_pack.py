#!/usr/bin/env python3
"""
scripts/closure_pack.py
File-backed claim closure packs: keys, build helpers, signing and stage-B verification.
The rules live in osiris_governance.closure / closure_verify (pure); this script only reads and
writes files, which the package itself never does (INV-13).

Pack layout (paths relative to the pack directory):

    <inputs bound by the closure: claim, evidence manifest, provenance, policy decision, ...>
    verification/pack-verification-report.json     stage A, written before the closure, bound by it
    closure.json                                   the closure (any formatting; its canonical form is signed)
    closure.json.sha256                            "sha256:<hex>" of the canonical bytes
    closure.sig                                    base64 Ed25519 signature over the canonical bytes
    verification/closure-verification-report.json  stage B, written by `verify`, never bound

Usage:

    python scripts/closure_pack.py keygen --private K.pem --public K.pub.pem
    python scripts/closure_pack.py check PACK
    python scripts/closure_pack.py sign PACK --private-key K.pem
    python scripts/closure_pack.py verify PACK --public-key K.pub.pem [--require-binding NAME ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from osiris_governance import signing  # noqa: E402
from osiris_governance.canonical import strict_parse_json  # noqa: E402
from osiris_governance.closure import (  # noqa: E402
    CLOSURE_FILE,
    CLOSURE_REPORT_FILE,
    DIGEST_FILE,
    SIGNATURE_FILE,
    closure_signing_payload,
    policy_violations,
    schema_violations,
)
from osiris_governance.closure_verify import (  # noqa: E402
    ClosureVerificationReport,
    SignedClosure,
    artifact_failures,
    sign_closure,
    verify_closure,
)
from osiris_governance.errors import ClosureValidationError, SchemaValidationError  # noqa: E402


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def resolve_inside(pack_dir: Path, relative: str) -> Path:
    """Resolves a pack-relative path, following symlinks; refuses anything outside the pack."""
    root = Path(pack_dir).resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise ValueError(f"{relative!r} resolves outside the pack")
    return target


def pack_hasher(pack_dir: Path):
    def hash_artifact(relative: str) -> Optional[str]:
        path = resolve_inside(pack_dir, relative)
        return file_sha256(path) if path.is_file() else None
    return hash_artifact


def artifact_entry(pack_dir: Path, relative: str) -> Dict[str, str]:
    """A {path, sha256} binding for the file as it is now. For closure builders."""
    return {"path": relative, "sha256": file_sha256(resolve_inside(pack_dir, relative))}


def _read_optional(path: Path) -> Optional[bytes]:
    return path.read_bytes() if path.is_file() else None


def write_closure(pack_dir: Path, doc: Mapping[str, Any]) -> Path:
    """Writes closure.json indented for people; the signature covers its canonical form.

    Refuses to replace a closure that already has a signature or digest beside it.
    """
    pack_dir = Path(pack_dir)
    for name in (SIGNATURE_FILE, DIGEST_FILE):
        if (pack_dir / name).exists():
            raise FileExistsError(f"{name} exists; a signed closure is not rewritten in place")
    closure_signing_payload(doc)  # refuse to write anything that cannot be canonicalized
    path = pack_dir / CLOSURE_FILE
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Writes a local Ed25519 development key pair (private key mode 0600); returns the fingerprint."""
    private_path, public_path = Path(private_path), Path(public_path)
    for path in (private_path, public_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing key file: {path}")
    private_pem = signing.generate_private_key_pem()
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private_pem)
    public_pem = signing.public_key_pem(private_pem)
    public_path.write_bytes(public_pem)
    return signing.public_key_fingerprint(signing.load_public_key_pem(public_pem))


def sign_pack(pack_dir: Path, private_key_path: Path) -> SignedClosure:
    """Validates the closure and bindings, then writes closure.json.sha256 and closure.sig."""
    pack_dir = Path(pack_dir)
    for name in (SIGNATURE_FILE, DIGEST_FILE):
        if (pack_dir / name).exists():
            raise FileExistsError(f"{name} already exists; refusing to re-sign")
    signed = sign_closure(
        (pack_dir / CLOSURE_FILE).read_bytes(), pack_hasher(pack_dir), Path(private_key_path).read_bytes()
    )
    (pack_dir / DIGEST_FILE).write_text(signed.digest_text, encoding="ascii")
    (pack_dir / SIGNATURE_FILE).write_text(signed.signature_text, encoding="ascii")
    return signed


def verify_pack(
    pack_dir: Path,
    public_key_path: Path,
    required_bindings: Sequence[str] = (),
    now: Optional[datetime] = None,
) -> ClosureVerificationReport:
    pack_dir = Path(pack_dir)
    digest = _read_optional(pack_dir / DIGEST_FILE)
    signature = _read_optional(pack_dir / SIGNATURE_FILE)
    return verify_closure(
        closure_bytes=_read_optional(pack_dir / CLOSURE_FILE),
        digest_text=digest.decode("ascii", errors="replace") if digest is not None else None,
        signature_text=signature.decode("ascii", errors="replace") if signature is not None else None,
        hash_artifact=pack_hasher(pack_dir),
        trusted_public_key_pem=Path(public_key_path).read_bytes(),
        verified_at=(now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        required_bindings=required_bindings,
        pack_name=pack_dir.resolve().name,
    )


def write_report(report: ClosureVerificationReport, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _print_lines(lines: Sequence[str]) -> None:
    for line in lines:
        print(f"  - {line}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Claim closure packs: keygen, check, sign, verify.")
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="create a local Ed25519 key pair (development signer)")
    keygen.add_argument("--private", required=True, type=Path)
    keygen.add_argument("--public", required=True, type=Path)
    fp = sub.add_parser("fingerprint", help="print a public key's sha256 fingerprint")
    fp.add_argument("--public", required=True, type=Path)
    check = sub.add_parser("check", help="schema, policy and artifact hashes; no keys involved")
    check.add_argument("pack", type=Path)
    sign = sub.add_parser("sign", help="validate, then write closure.json.sha256 and closure.sig")
    sign.add_argument("pack", type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    verify = sub.add_parser("verify", help="stage-B verification; writes the closure verification report")
    verify.add_argument("pack", type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--require-binding", action="append", default=[], metavar="NAME")
    verify.add_argument("--report", default=None,
                        help=f"report path (default PACK/{CLOSURE_REPORT_FILE}; '-' prints only)")
    args = parser.parse_args(argv)

    if args.command == "keygen":
        print(generate_keypair(args.private, args.public))
        return 0
    if args.command == "fingerprint":
        print(signing.public_key_fingerprint(signing.load_public_key_pem(args.public.read_bytes())))
        return 0
    if args.command == "check":
        try:
            doc = strict_parse_json((args.pack / CLOSURE_FILE).read_bytes())
        except (SchemaValidationError, OSError) as exc:
            print(f"FAIL\n  - {exc}")
            return 1
        problems = schema_violations(doc)
        if not problems:
            problems = policy_violations(doc) + artifact_failures(doc, pack_hasher(args.pack))
        print("PASS" if not problems else "FAIL")
        _print_lines(problems)
        return 0 if not problems else 1
    if args.command == "sign":
        try:
            signed = sign_pack(args.pack, args.private_key)
        except (ClosureValidationError, SchemaValidationError) as exc:
            print("REFUSED")
            _print_lines(getattr(exc, "violations", [str(exc)]))
            return 1
        print(f"signed {signed.closure_sha256} with {signed.public_key_fingerprint}")
        return 0

    report = verify_pack(args.pack, args.public_key, args.require_binding)
    for item in report.checks:
        print(f"{item.status:7s} {item.name}")
        _print_lines(item.details)
    print(report.status)
    if args.report != "-":
        write_report(report, Path(args.report) if args.report else Path(args.pack) / CLOSURE_REPORT_FILE)
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
