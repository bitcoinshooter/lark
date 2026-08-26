#!/usr/bin/env python3
"""
Independently verify Kern's multisig interoperability fixture.

Shares no code with the Java implementation or with Kern. The AEXB envelope
layout is recovered from the bytes and asserted rather than assumed, so a
change to the format shows up as a parse failure instead of a silent
misreading.

Checks, per slot:
  - the host commitment re-derives as tagged_hash("s2c/ecdsa/data", rho)
  - the sign-to-contract relation holds for the carried signature
  - the signature is a valid ECDSA signature for the carried pubkey and hash

Then, for the input carrying two protected signatures, that neither slot's
opening and entropy can be satisfied by the other slot's signature, and that
neither signature verifies under the other's pubkey.

Finally, that every signature in the envelope appears verbatim in the signed
PSBT, so the two artifacts are one claim rather than two agreeing ones.

Usage:
  python3 verify_kern_multisig.py path/to/kern-multisig-two-signatures-per-input-v1.json
"""

import base64
import hashlib
import json
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

SLOT_COUNT_OFFSET = 76
M3_TAIL = 32   # host entropy
M4_TAIL = 64   # compact signature


def inv(a, m=P):
    return pow(a, m - 2, m)


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        l = (3 * p[0] * p[0] * inv(2 * p[1])) % P
    else:
        l = ((q[1] - p[1]) * inv(q[0] - p[0])) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)


def mul(k, p):
    r = None
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def decompress(b):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError(f"not a compressed point: {b.hex()}")
    x = int.from_bytes(b[1:], "big")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - (x * x * x + 7)) % P != 0:
        raise ValueError(f"point not on curve: {b.hex()}")
    return (x, P - y if y % 2 != b[0] % 2 else y)


def tagged(tag, msg):
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h + h + msg).digest()


def parse_envelope(hexstr, tail, expected_stage):
    """Slot records from an AEXB message. Raises if the layout does not fit."""
    b = bytes.fromhex(hexstr)
    if b[:4] != b"AEXB":
        raise ValueError(f"bad magic: {b[:4]!r}")
    if b[6] != expected_stage:
        raise ValueError(f"expected stage {expected_stage}, envelope says {b[6]}")
    count = int.from_bytes(b[SLOT_COUNT_OFFSET:SLOT_COUNT_OFFSET + 2], "big")
    i = SLOT_COUNT_OFFSET + 2
    slots = []
    for _ in range(count):
        inp = int.from_bytes(b[i:i + 4], "big"); i += 4
        key = int.from_bytes(b[i:i + 4], "big"); i += 4
        pub = b[i:i + 33]; i += 33
        msg = b[i:i + 32]; i += 32
        com = b[i:i + 32]; i += 32
        opn = b[i:i + 33]; i += 33
        last = b[i:i + tail]; i += tail
        slots.append(dict(input=inp, key=key, pubkey=pub,
                          message_hash=msg, commitment=com, opening=opn, tail=last))
    if i != len(b):
        raise ValueError(f"slot layout consumed {i} of {len(b)} bytes")
    return slots


def s2c_holds(opening, entropy, sig_r):
    t = int.from_bytes(tagged("s2c/ecdsa/point", opening + entropy), "big")
    if not 0 < t < N:
        return False
    R = add(decompress(opening), mul(t, G))
    return R is not None and R[0] % N == sig_r


def ecdsa_ok(pubkey, message_hash, sig):
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    si = inv(s, N)
    z = int.from_bytes(message_hash, "big")
    pt = add(mul(z * si % N, G), mul(r * si % N, decompress(pubkey)))
    return pt is not None and pt[0] % N == r


def der_with_sighash(sig, sighash=1):
    def trim(x):
        x = x.lstrip(b"\x00") or b"\x00"
        return b"\x00" + x if x[0] & 0x80 else x
    r, s = trim(sig[:32]), trim(sig[32:])
    body = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
    return b"\x30" + bytes([len(body)]) + body + bytes([sighash])


def main():
    if len(sys.argv) != 2:
        print(__doc__.strip())
        return 2
    fixture = json.load(open(sys.argv[1]))

    m3 = parse_envelope(fixture["message_3_hex"], M3_TAIL, 3)
    m4 = parse_envelope(fixture["message_4_hex"], M4_TAIL, 4)
    if len(m3) != len(m4):
        raise ValueError("slot count differs between message 3 and message 4")
    rho = {(s["input"], s["pubkey"]): s["tail"] for s in m3}

    failures = []

    print(f"{fixture.get('schema','fixture')} - {len(m4)} slots\n")
    for s in m4:
        key = (s["input"], s["pubkey"])
        if key not in rho:
            failures.append(f"slot {key[0]} has no matching entropy in message 3")
            continue
        entropy = rho[key]
        derived = tagged("s2c/ecdsa/data", entropy) == s["commitment"]
        holds = s2c_holds(s["opening"], entropy, int.from_bytes(s["tail"][:32], "big"))
        valid = ecdsa_ok(s["pubkey"], s["message_hash"], s["tail"])
        print(f"  input {s['input']}  {s['pubkey'].hex()[:12]}..  "
              f"commitment={'ok' if derived else 'MISMATCH'}  "
              f"s2c={'ok' if holds else 'FAIL'}  ecdsa={'ok' if valid else 'FAIL'}")
        for ok, what in ((derived, "commitment"), (holds, "s2c"), (valid, "ecdsa")):
            if not ok:
                failures.append(f"input {s['input']} {s['pubkey'].hex()[:12]}: {what}")

    idx = fixture.get("multisig_input_index")
    shared = [s for s in m4 if s["input"] == idx]
    if len(shared) == 2:
        a, b = shared
        print(f"\n  input {idx} carries two protected signatures")
        checks = [
            ("A opening and entropy vs B signature",
             s2c_holds(a["opening"], rho[(a["input"], a["pubkey"])],
                       int.from_bytes(b["tail"][:32], "big"))),
            ("B opening and entropy vs A signature",
             s2c_holds(b["opening"], rho[(b["input"], b["pubkey"])],
                       int.from_bytes(a["tail"][:32], "big"))),
            ("B signature under A pubkey",
             ecdsa_ok(a["pubkey"], a["message_hash"], b["tail"])),
            ("A signature under B pubkey",
             ecdsa_ok(b["pubkey"], b["message_hash"], a["tail"])),
        ]
        for name, held in checks:
            print(f"    {name}: {'HELD - should not' if held else 'does not hold'}")
            if held:
                failures.append(f"cross-key: {name} held")
    else:
        print(f"\n  note: expected two slots on input {idx}, found {len(shared)}")

    raw = base64.b64decode(fixture["signed_psbt_base64"])
    digest = hashlib.sha256(raw).hexdigest()
    print(f"\n  signed PSBT sha256 matches published: {digest == fixture['signed_psbt_sha256']}")
    if digest != fixture["signed_psbt_sha256"]:
        failures.append("signed PSBT digest mismatch")
    for s in m4:
        present = der_with_sighash(s["tail"]) in raw
        print(f"    input {s['input']} {s['pubkey'].hex()[:12]}.. signature in signed PSBT: {present}")
        if not present:
            failures.append(f"input {s['input']} signature absent from signed PSBT")

    print()
    if failures:
        print("FAIL")
        for f in failures:
            print("  -", f)
        return 1
    print("PASS - every slot verifies, no cross-key substitution holds, and the")
    print("       envelope signatures are the ones in the signed PSBT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
