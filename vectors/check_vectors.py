#!/usr/bin/env python3
"""
Independent conformance check of the published anti-exfil crypto corpus.

Deliberately shares no code with the Java verifier the vectors came from. Point
arithmetic, tagged hashing, DER parsing and the s2c relation are all rewritten
here from the construction as documented, so agreement between this and the
corpus is evidence rather than a tautology. If both were wrong in the same way
the corpus would still pass, but that requires the same mistake made twice
independently, which is the bar worth clearing before handing the file to
another implementer.

Checks, in order:
  1. Structural  - schema fields present, ids unique, hex lengths correct.
  2. Derivation  - host_commitment really is tagged_hash("s2c/ecdsa/data", rho).
  3. Encoding    - strict DER, canonical integers, low-S, scalars in range.
  4. Relation    - sig.r == (R0 + t*G).x mod n, and the stated verdict matches.
                   Where a case also carries pubkey and message_hash, ordinary
                   ECDSA is verified too and expected_combined must equal
                   expected_s2c AND expected_ecdsa. Cases without them are
                   checked for the s2c relation alone, so both corpora run
                   against this checker unchanged.
  5. Boundary    - the tweak acceptance rule over its four cases.
  6. Coverage    - the corpus contains both accepting and rejecting cases, and
                   each declared class behaves as its name claims.

Usage: python3 check_vectors.py vectors/lark-ae-ecdsa-crypto-v1.json
"""

import hashlib
import json
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


# --- curve ---

def inv(a, m=P):
    return pow(a, m - 2, m)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] * inv(2 * p[1])) % P
    else:
        lam = ((q[1] - p[1]) * inv(q[0] - p[0])) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def point_mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r


def decompress(b):
    """33-byte SEC1 -> affine point. Raises if malformed or off-curve."""
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad point encoding")
    x = int.from_bytes(b[1:], "big")
    if x >= P:
        raise ValueError("x out of field range")
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        raise ValueError("point not on curve")
    if (y & 1) != (b[0] == 3):
        y = P - y
    return (x, y)


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


# --- strict DER ---

def parse_der_strict(der):
    """
    BIP66-style strict parse, tolerating one trailing sighash byte.
    Returns (r, s). Raises on any encoding the corpus should not contain.
    """
    if len(der) >= 2 and der[1] == len(der) - 3:
        der = der[:-1]  # drop trailing sighash byte
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not a DER sequence")
    if der[1] != len(der) - 2:
        raise ValueError("sequence length mismatch")
    if der[2] != 0x02:
        raise ValueError("r is not an INTEGER")
    rlen = der[3]
    if rlen == 0 or 4 + rlen + 2 > len(der):
        raise ValueError("bad r length")
    rb = der[4:4 + rlen]
    off = 4 + rlen
    if der[off] != 0x02:
        raise ValueError("s is not an INTEGER")
    slen = der[off + 1]
    if slen == 0 or off + 2 + slen != len(der):
        raise ValueError("bad s length")
    sb = der[off + 2:off + 2 + slen]
    for name, v in (("r", rb), ("s", sb)):
        if v[0] & 0x80:
            raise ValueError(f"{name} is negative")
        if len(v) > 1 and v[0] == 0x00 and not (v[1] & 0x80):
            raise ValueError(f"{name} has a redundant leading zero")
    return int.from_bytes(rb, "big"), int.from_bytes(sb, "big")


def ecdsa_verify(pubkey33, msg32, r, s):
    """Textbook ECDSA verification. Independent of any library."""
    if not (0 < r < N and 0 < s < N):
        return False
    Q = decompress(pubkey33)
    z = int.from_bytes(msg32, "big")
    w = pow(s, N - 2, N)
    u1, u2 = (z * w) % N, (r * w) % N
    X = point_add(point_mul(u1), point_mul(u2, Q))
    if X is None:
        return False
    return X[0] % N == r


def acceptable_tweak(t32):
    if len(t32) != 32:
        return False
    t = int.from_bytes(t32, "big")
    return t != 0 and t < N


def s2c_holds(der, opening, rho):
    r, s = parse_der_strict(der)
    if not (0 < r < N and 0 < s < N):
        return False, "scalar out of range"
    if s > N // 2:
        return False, "high S"
    t32 = tagged_hash("s2c/ecdsa/point", opening + rho)
    if not acceptable_tweak(t32):
        return False, "tweak not acceptable"
    R = point_add(decompress(opening), point_mul(int.from_bytes(t32, "big")))
    if R is None:
        return False, "point at infinity"
    return (R[0] % N == r), "r matches committed point" if R[0] % N == r else "r does not match"


# --- checks ---

def main(path):
    doc = json.load(open(path))
    failures, notes = [], []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    # 1. structural
    for field in ("schema", "construction", "encoding_rules", "vectors", "tweak_boundary"):
        check(field in doc, f"missing top-level field: {field}")
    vectors = doc.get("vectors", [])
    ids = [v["id"] for v in vectors]
    check(len(ids) == len(set(ids)), "duplicate vector ids")
    check(len(vectors) > 0, "no vectors")

    for v in vectors:
        for field in ("id", "class", "der_sig", "signer_commitment", "host_entropy",
                      "host_commitment", "expected_s2c"):
            check(field in v, f"{v.get('id','?')}: missing field {field}")
        check(len(v["signer_commitment"]) == 66, f"{v['id']}: opening is not 33 bytes")
        check(len(v["host_entropy"]) == 64, f"{v['id']}: entropy is not 32 bytes")
        check(len(v["host_commitment"]) == 64, f"{v['id']}: commitment is not 32 bytes")
        check(isinstance(v["expected_s2c"], bool), f"{v['id']}: expected_s2c not boolean")
        complete = v.get("pubkey") is not None and v.get("message_hash") is not None
        if complete:
            check(len(v["pubkey"]) == 66, f"{v['id']}: pubkey is not 33 bytes")
            check(len(v["message_hash"]) == 64, f"{v['id']}: message_hash is not 32 bytes")
            check(isinstance(v.get("expected_ecdsa"), bool),
                  f"{v['id']}: complete tuple must state expected_ecdsa")
            check(isinstance(v.get("expected_combined"), bool),
                  f"{v['id']}: complete tuple must state expected_combined")
            if isinstance(v.get("expected_ecdsa"), bool) and isinstance(v.get("expected_combined"), bool):
                check(v["expected_combined"] == (v["expected_s2c"] and v["expected_ecdsa"]),
                      f"{v['id']}: expected_combined must equal expected_s2c AND expected_ecdsa")
        else:
            check(v.get("expected_ecdsa") is None and v.get("expected_combined") is None,
                  f"{v['id']}: ecdsa verdicts must be null without pubkey and message_hash")

    # 2-4. per vector
    for v in vectors:
        rho = bytes.fromhex(v["host_entropy"])
        opening = bytes.fromhex(v["signer_commitment"])
        der = bytes.fromhex(v["der_sig"])

        want_commit = tagged_hash("s2c/ecdsa/data", rho).hex()
        check(want_commit == v["host_commitment"],
              f"{v['id']}: host_commitment does not match tagged_hash of entropy")

        try:
            decompress(opening)
        except ValueError as e:
            failures.append(f"{v['id']}: opening invalid ({e})")
            continue

        try:
            parse_der_strict(der)
        except ValueError as e:
            failures.append(f"{v['id']}: signature is not strict DER ({e}) - "
                            f"encoding failures belong in separate tests, not this corpus")
            continue

        got, why = s2c_holds(der, opening, rho)
        check(got == v["expected_s2c"],
              f"{v['id']}: expected_s2c={v['expected_s2c']} but independent check says {got} ({why})")

        if v.get("pubkey") is not None and v.get("message_hash") is not None:
            r, sv = parse_der_strict(der)
            got_ecdsa = ecdsa_verify(bytes.fromhex(v["pubkey"]),
                                     bytes.fromhex(v["message_hash"]), r, sv)
            check(got_ecdsa == v.get("expected_ecdsa"),
                  f"{v['id']}: expected_ecdsa={v.get('expected_ecdsa')} but independent check says {got_ecdsa}")
            # compact and DER, when both given, must be the same (r, s)
            if v.get("signature_compact") is not None:
                compact = bytes.fromhex(v["signature_compact"])
                check(len(compact) == 64, f"{v['id']}: signature_compact is not 64 bytes")
                if len(compact) == 64:
                    check(int.from_bytes(compact[:32], "big") == r
                          and int.from_bytes(compact[32:], "big") == sv,
                          f"{v['id']}: signature_compact and der_sig are different (r, s)")

    # 5. boundary
    for b in doc.get("tweak_boundary", []):
        t32 = bytes.fromhex(b["tweak32"])
        check(len(t32) == 32, f"{b['id']}: tweak32 is not 32 bytes")
        check(acceptable_tweak(t32) == b["acceptable"],
              f"{b['id']}: acceptable={b['acceptable']} but independent check disagrees")
    boundary_ids = {b["id"] for b in doc.get("tweak_boundary", [])}
    for required in ("tweak-zero", "tweak-at-order"):
        check(required in boundary_ids, f"boundary corpus is missing {required}")

    # 6. coverage
    accepting = [v for v in vectors if v["expected_s2c"]]
    rejecting = [v for v in vectors if not v["expected_s2c"]]
    check(accepting and rejecting, "corpus must contain both accepting and rejecting cases")
    notes.append(f"{len(accepting)} accepting, {len(rejecting)} rejecting")
    complete_cases = [v for v in vectors if v.get("pubkey") and v.get("message_hash")]
    notes.append(f"{len(complete_cases)} complete-tuple (s2c + ecdsa), "
                 f"{len(vectors) - len(complete_cases)} s2c-only")
    # A class describes the overall verdict, which for a complete tuple is the
    # combined one. Keying this on expected_s2c alone was wrong: a case with a
    # committed nonce point and a signature that does not verify is legitimately
    # expected_s2c=true and expected_combined=false, and the old rule called
    # that a corpus error.
    by_class = {}
    for v in vectors:
        verdict = v["expected_combined"] if v.get("expected_combined") is not None else v["expected_s2c"]
        by_class.setdefault(v["class"], []).append(verdict)
    for cls, verdicts in sorted(by_class.items()):
        if cls == "honest_signer":
            check(all(verdicts), "honest_signer cases must all accept")
        else:
            check(not any(verdicts), f"{cls} cases must all be rejected overall")
        notes.append(f"class {cls}: {len(verdicts)}")

    # a corpus of only-rejects would pass a broken verifier that rejects everything
    check(len(accepting) >= 2, "too few accepting cases to catch a reject-everything verifier")

    print(f"corpus: {path}")
    for n in notes:
        print(f"  {n}")
    if failures:
        print(f"\nFAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nPASS - {len(vectors)} vectors and {len(doc.get('tweak_boundary', []))} boundary cases "
          f"agree with an independent implementation")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors/lark-ae-ecdsa-crypto-v1.json"))
