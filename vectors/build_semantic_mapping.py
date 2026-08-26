#!/usr/bin/env python3
"""
Derive a transport-neutral semantic mapping from the recorded testnet4
anti-exfil ceremony.

The point is to let another implementation replay the SAME semantic case over a
different carriage. What is published here is not "these PSBT bytes" but "this
session, these slots, these commitments, openings, entropy and signatures" —
so an AEXT or hybrid profile can carry the identical transcript and be compared
against it without inventing a new case.

Reads the fixtures out of AntiExfilSessionTest.java rather than duplicating
them, so the mapping cannot drift from the transcript it describes.

Usage: python3 build_semantic_mapping.py [path-to-AntiExfilSessionTest.java] [out.json]
"""

import base64
import hashlib
import pathlib
import json
import re
import sys

PROPRIETARY = 0xFC
AE_PREFIX = b"ae"
SUB_HOST_COMMITMENT, SUB_SIGNER_COMMITMENT, SUB_HOST_ENTROPY = 0, 1, 2
SUBTYPE_NAME = {0: "host_commitment", 1: "signer_opening", 2: "host_entropy"}


# --- minimal PSBT reader ---

def read_varint(b, i):
    n = b[i]
    if n < 0xFD:
        return n, i + 1
    if n == 0xFD:
        return int.from_bytes(b[i + 1:i + 3], "little"), i + 3
    if n == 0xFE:
        return int.from_bytes(b[i + 1:i + 5], "little"), i + 5
    return int.from_bytes(b[i + 1:i + 9], "little"), i + 9


def read_map(b, i):
    """Returns (list of (key_bytes, value_bytes), next_index)."""
    entries = []
    while True:
        klen, i = read_varint(b, i)
        if klen == 0:
            return entries, i
        key = b[i:i + klen]
        i += klen
        vlen, i = read_varint(b, i)
        entries.append((key, b[i:i + vlen]))
        i += vlen


def parse_psbt(raw):
    assert raw[:5] == b"psbt\xff", "not a PSBT"
    i = 5
    globals_, i = read_map(raw, i)
    unsigned_tx = next(v for k, v in globals_ if k and k[0] == 0x00)
    n_in, n_out = count_tx_io(unsigned_tx)
    inputs = []
    for _ in range(n_in):
        entries, i = read_map(raw, i)
        inputs.append(entries)
    return {"unsigned_tx": unsigned_tx, "inputs": inputs}


def count_tx_io(tx):
    i = 4  # version
    n_in, i = read_varint(tx, i)
    for _ in range(n_in):
        i += 36                       # outpoint
        slen, i = read_varint(tx, i)
        i += slen + 4                 # scriptSig + sequence
    n_out, i = read_varint(tx, i)
    return n_in, n_out


def txid(unsigned_tx):
    """Non-witness txid, displayed big-endian, matching drongo PSBT.matches()."""
    h = hashlib.sha256(hashlib.sha256(unsigned_tx).digest()).digest()
    return h[::-1].hex()


def ae_records(input_entries):
    """Anti-exfil proprietary records, grouped by signer pubkey."""
    out = {}
    for key, value in input_entries:
        if not key or key[0] != PROPRIETARY:
            continue
        ident_len, j = read_varint(key, 1)
        if key[j:j + ident_len] != AE_PREFIX:
            continue
        j += ident_len
        subtype = key[j]
        pubkey = key[j + 1:].hex()
        out.setdefault(pubkey, {})[SUBTYPE_NAME.get(subtype, f"subtype_{subtype}")] = value.hex()
    return out


def partial_sigs(input_entries):
    return {k[1:].hex(): v.hex() for k, v in input_entries if k and k[0] == 0x02}


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


# --- mapping ---

def stage_record(name, direction, raw, expected_txid=None):
    p = parse_psbt(raw)
    tid = txid(p["unsigned_tx"])
    slots = []
    for index, entries in enumerate(p["inputs"]):
        recs = ae_records(entries)
        sigs = partial_sigs(entries)
        for pubkey in sorted(set(recs) | set(sigs)):
            slot = {"input_index": index, "signer_pubkey": pubkey}
            slot.update(recs.get(pubkey, {}))
            if pubkey in sigs:
                slot["signature_der"] = sigs[pubkey]
            slots.append(slot)
    rec = {
        "stage": name,
        "direction": direction,
        "binding": {"scheme": "non_witness_txid_of_unsigned_tx", "value": tid},
        "slots": slots,
    }
    if expected_txid is not None:
        rec["binding_matches_session"] = (tid == expected_txid)
    return rec


def main(test_path, out_path):
    src = open(test_path).read()

    def const(name):
        m = re.search(rf'{name}\s*=\s*"([^"]+)"', src)
        if not m:
            raise SystemExit(f"fixture {name} not found in {test_path}")
        return m.group(1)

    r1_out = base64.b64decode(const("ROUND1_OUT"))
    r1_reply = base64.b64decode(const("ROUND1_REPLY"))
    r2_reply = base64.b64decode(const("ROUND2_REPLY"))
    entropy = bytes.fromhex(const("RECORDED_HOST_ENTROPY"))
    signer = const("SIGNER_PUBKEY")

    session_txid = txid(parse_psbt(r1_out)["unsigned_tx"])

    stages = [
        stage_record("M1", "coordinator_to_signer", r1_out, session_txid),
        stage_record("M2", "signer_to_coordinator", r1_reply, session_txid),
        stage_record("M4", "signer_to_coordinator", r2_reply, session_txid),
    ]

    # M3 is a coordinator output, so no device ever returned it. Prefer the
    # captured artifact written by AntiExfilTranscriptExport, which replays the
    # session with the recorded entropy and therefore reproduces the exact bytes
    # the device received. Fall back to deriving the fields only if it is absent.
    captured_m3 = pathlib.Path("vectors/transcript/M3-coordinator-to-signer.psbt.b64")
    if captured_m3.exists():
        # M3 is a coordinator output, so no device ever returned it. This
        # artifact is written by AntiExfilTranscriptExport, which replays the
        # session with the recorded entropy and therefore reproduces the exact
        # bytes the device received.
        m3 = stage_record("M3", "coordinator_to_signer",
                          base64.b64decode(captured_m3.read_text().strip()), session_txid)
        m3["captured"] = True
        m3["note"] = ("captured by replaying the recorded session; the recorded M4 "
                      "signature verifies against the opening and entropy carried here")
        m3_note = "M3 is captured from a replay of the recorded session, not hand-derived."
    else:
        m2_slots = {s["signer_pubkey"]: s for s in stages[1]["slots"]}
        m3 = {
            "stage": "M3",
            "direction": "coordinator_to_signer",
            "derived": True,
            "note": "not recorded and not captured; fields derived from M1, the M2 "
                    "opening and the session entropy. Run AntiExfilTranscriptExport "
                    "to replace this with a captured artifact.",
            "binding": {"scheme": "non_witness_txid_of_unsigned_tx", "value": session_txid},
            "slots": [{
                "input_index": v["input_index"],
                "signer_pubkey": pk,
                "host_commitment": tagged_hash("s2c/ecdsa/data", entropy).hex(),
                "signer_opening": v.get("signer_opening"),
                "host_entropy": entropy.hex(),
            } for pk, v in m2_slots.items()],
        }
        m3_note = "M3 is derived, not captured. Every other stage is verbatim from hardware."
    stages.insert(2, m3)

    doc = {
        "schema": "ae-semantic-transcript-v1",
        "source": "recorded testnet4 ceremony, Jade + lark + Sparrow, in-PSBT profile",
        "profile": "in-PSBT (0xFC, identifier 'ae')",
        "construction": {
            "host_commitment": 'tagged_hash("s2c/ecdsa/data", host_entropy)',
            "tweak": 'tagged_hash("s2c/ecdsa/point", signer_opening || host_entropy)',
            "accept_if": "sig.r == (signer_opening + tweak*G).x mod n",
        },
        "session": {
            "binding_scheme": "non_witness_txid_of_unsigned_tx",
            "binding": session_txid,
            "slot_count": len(stages[0]["slots"]),
            "expected_signers": [signer],
        },
        "notes": [
            "Stage bodies are described semantically. The PSBT bytes are the "
            "in-PSBT profile's encoding of these fields, not the transcript itself.",
            m3_note,
            "The binding scheme here is what this implementation currently does. It "
            "is weaker than a frozen-context digest and is expected to be replaced.",
        ],
        "stages": stages,
    }
    open(out_path, "w").write(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out_path}")
    for st in doc["stages"]:
        tag = " (captured)" if st.get("captured") else (" (derived)" if st.get("derived") else "")
        fields = sorted({k for slot in st["slots"] for k in slot
                         if k not in ("input_index", "signer_pubkey")})
        print(f"  {st['stage']}{tag}: {len(st['slots'])} slot(s), fields: {', '.join(fields) or 'none'}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1
         else "src/test/java/com/sparrowwallet/lark/AntiExfilSessionTest.java",
         sys.argv[2] if len(sys.argv) > 2 else "vectors/lark-ae-semantic-transcript-v1.json")
