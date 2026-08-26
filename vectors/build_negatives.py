#!/usr/bin/env python3
"""
Build the six shared adversarial cases as in-PSBT fixtures.

These are the negatives FractalEncrypt proposed for cross-profile conformance.
Each is produced by mutating the captured testnet4 transcript, so the semantic
case is identical across profiles and only the carriage differs.

The point of publishing these is not to demonstrate that lark rejects them. It
is to establish which ones any conforming coordinator must reject, and — where
this implementation does not yet — to say so with a fixture rather than a
sentence.

Writes:
  vectors/negatives/<id>.psbt.b64   the mutated M4 response
  vectors/lark-ae-negatives-v1.json the case manifest with expected reason class

Usage: python3 vectors/build_negatives.py
"""

import base64
import hashlib
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from build_semantic_mapping import (  # noqa: E402
    PROPRIETARY, AE_PREFIX, read_map, read_varint, parse_psbt, txid,
)

REPO = pathlib.Path(__file__).resolve().parent.parent
TEST = REPO / "src/test/java/com/sparrowwallet/lark/AntiExfilSessionTest.java"
OUT_DIR = REPO / "vectors/negatives"
MANIFEST = REPO / "vectors/lark-ae-negatives-v1.json"


def const(name):
    return re.search(rf'{name}\s*=\s*"([^"]+)"', TEST.read_text()).group(1)


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def split(raw):
    """(globals, [input maps], tail bytes) preserving entry order."""
    assert raw[:5] == b"psbt\xff"
    i = 5
    g, i = read_map(raw, i)
    tx = next(v for k, v in g if k and k[0] == 0x00)
    j = 4
    n_in, j = read_varint(tx, j)
    ins = []
    for _ in range(n_in):
        e, i = read_map(raw, i)
        ins.append(e)
    return g, ins, raw[i:]


def emit_map(entries):
    out = b""
    for k, v in entries:
        out += write_varint(len(k)) + k + write_varint(len(v)) + v
    return out + b"\x00"


def rebuild(g, ins, tail):
    return b"psbt\xff" + emit_map(g) + b"".join(emit_map(e) for e in ins) + tail


def ae_key(subtype, pubkey):
    return bytes([PROPRIETARY]) + write_varint(len(AE_PREFIX)) + AE_PREFIX + bytes([subtype]) + pubkey


def is_ae(key):
    if not key or key[0] != PROPRIETARY:
        return False
    ident_len, j = read_varint(key, 1)
    return key[j:j + ident_len] == AE_PREFIX


def ae_subtype(key):
    ident_len, j = read_varint(key, 1)
    return key[j + ident_len]


# --- mutations ---

def changed_signing_context(raw, pubkey):
    """Alter an output amount so the transaction differs from the frozen one."""
    g, ins, tail = split(raw)
    g2 = []
    for k, v in g:
        if k and k[0] == 0x00:
            tx = bytearray(v)
            # walk to first output value and bump it
            i = 4
            n_in, i = read_varint(bytes(tx), i)
            for _ in range(n_in):
                i += 36
                sl, i = read_varint(bytes(tx), i)
                i += sl + 4
            n_out, i = read_varint(bytes(tx), i)
            amount = int.from_bytes(tx[i:i + 8], "little")
            tx[i:i + 8] = (amount - 1000).to_bytes(8, "little")
            v = bytes(tx)
        g2.append((k, v))
    return rebuild(g2, ins, tail)


def duplicate_ae_record(raw, pubkey):
    """Same ae key appearing twice with different values."""
    g, ins, tail = split(raw)
    entries = list(ins[0])
    for idx, (k, v) in enumerate(entries):
        if is_ae(k) and ae_subtype(k) == 1:
            entries.insert(idx + 1, (k, bytes([v[0]]) + bytes(32)))
            break
    ins[0] = entries
    return rebuild(g, ins, tail)


def unknown_proprietary_record(raw, pubkey):
    """An unrecognised ae subtype the coordinator never asked for."""
    g, ins, tail = split(raw)
    ins[0] = list(ins[0]) + [(ae_key(0x7F, pubkey), b"\xde\xad\xbe\xef")]
    return rebuild(g, ins, tail)


def cross_key_association(raw, pubkey):
    """Signature re-filed under a different pubkey than the one that signed."""
    g, ins, tail = split(raw)
    other = bytes([0x03]) + pubkey[1:]
    entries = []
    for k, v in ins[0]:
        if k and k[0] == 0x02:
            entries.append((bytes([0x02]) + other, v))
        else:
            entries.append((k, v))
    ins[0] = entries
    return rebuild(g, ins, tail)


def unrelated_valid_signature(raw, pubkey):
    """
    An additional signature under another key, alongside a corrupted signature
    for the expected key. This is the case that motivated binding both relations
    to the same signature: a verifier that asks 'does any signature on this
    input verify' can be satisfied by the wrong one.
    """
    g, ins, tail = split(raw)
    other = bytes([0x03]) + pubkey[1:]
    entries = []
    original = None
    for k, v in ins[0]:
        if k and k[0] == 0x02 and k[1:] == pubkey:
            original = v
            corrupted = bytearray(v)
            corrupted[-2] ^= 0xFF          # break s, leave r intact
            entries.append((k, bytes(corrupted)))
        else:
            entries.append((k, v))
    if original is not None:
        entries.append((bytes([0x02]) + other, original))
    ins[0] = entries
    return rebuild(g, ins, tail)


def mutation_outside_allowlist(raw, pubkey):
    """A standard field the signer had no business changing: the sighash type."""
    g, ins, tail = split(raw)
    entries = []
    for k, v in ins[0]:
        if k and k[0] == 0x03:
            entries.append((k, (0x83).to_bytes(4, "little")))
        else:
            entries.append((k, v))
    ins[0] = entries
    return rebuild(g, ins, tail)


def stripped_ae_records(raw, pubkey):
    """Generic trim behaviour: every ae record dropped from the response."""
    g, ins, tail = split(raw)
    ins[0] = [(k, v) for k, v in ins[0] if not is_ae(k)]
    return rebuild(g, ins, tail)


CASES = [
    ("changed-signing-context", changed_signing_context, "BINDING",
     "output amount altered, so the response is not for the frozen transaction"),
    ("duplicate-ae-record", duplicate_ae_record, "STRUCTURE",
     "the same anti-exfil key appears twice with different values"),
    ("unknown-ae-subtype", unknown_proprietary_record, "STRUCTURE",
     "an unrecognised anti-exfil subtype the coordinator never requested"),
    ("cross-key-signature", cross_key_association, "MISSING",
     "the signature is filed under a pubkey that did not produce it"),
    ("unrelated-valid-signature", unrelated_valid_signature, "ECDSA",
     "a valid signature for another key sits beside a corrupted one for the expected key"),
    ("mutation-outside-allowlist", mutation_outside_allowlist, "STRUCTURE",
     "the signer changed the sighash type in its response"),
    ("stripped-ae-records", stripped_ae_records, "MISSING",
     "generic trim dropped every anti-exfil record from the response"),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    m4 = base64.b64decode(const("ROUND2_REPLY"))
    pubkey = bytes.fromhex(const("SIGNER_PUBKEY"))
    session = txid(parse_psbt(base64.b64decode(const("ROUND1_OUT")))["unsigned_tx"])

    cases = []
    for cid, fn, reason, description in CASES:
        mutated = fn(m4, pubkey)
        assert mutated != m4, f"{cid} produced no change"
        path = OUT_DIR / f"{cid}.psbt.b64"
        path.write_text(base64.b64encode(mutated).decode() + "\n")
        cases.append({
            "id": cid,
            "stage": "M4",
            "expected_reason": reason,
            "description": description,
            "artifact": f"vectors/negatives/{cid}.psbt.b64",
            "sha256": hashlib.sha256(mutated).hexdigest(),
            "bytes": len(mutated),
        })
        print(f"  {cid:28} {reason:10} {len(mutated)} bytes")

    MANIFEST.write_text(json.dumps({
        "schema": "ae-semantic-negatives-v1",
        "profile": "in-PSBT (0xFC, identifier 'ae')",
        "base_transcript": "vectors/lark-ae-semantic-transcript-v1.json",
        "session_binding": session,
        "notes": [
            "Each case mutates the captured M4 response from the recorded testnet4 "
            "ceremony, so the semantic case is identical across transport profiles.",
            "expected_reason uses the error classes in the shared state machine draft. "
            "Those classes are proposed, not agreed.",
            "A conforming coordinator must reject every case. Which reason it reports "
            "is only meaningful once the taxonomy is settled.",
        ],
        "cases": cases,
    }, indent=2) + "\n")
    print(f"\nwrote {MANIFEST.relative_to(REPO)} with {len(cases)} cases")


if __name__ == "__main__":
    main()
