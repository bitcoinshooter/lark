"""
Does the in-PSBT profile have a stable 'base PSBT' across a real device round-trip?

Fractal's option (a) for binding is: strip recognised anti-exfil fields,
canonically serialise the remainder, hash that. That only works if the remainder
is actually stable when a device parses and re-serialises the PSBT. Measure it
against the recorded testnet4 ceremony rather than assuming.
"""
import base64, hashlib, re, sys
sys.path.insert(0, 'vectors')
from build_semantic_mapping import parse_psbt, read_map, read_varint, PROPRIETARY, AE_PREFIX

src = open('src/test/java/com/sparrowwallet/lark/AntiExfilSessionTest.java').read()
def const(n):
    return re.search(rf'{n}\s*=\s*"([^"]+)"', src).group(1)

def split_maps(raw):
    """Return (globals_entries, [input_entries], tail_offset) with raw slices."""
    assert raw[:5] == b"psbt\xff"
    i = 5
    g, i = read_map(raw, i)
    tx = next(v for k, v in g if k and k[0] == 0x00)
    # count inputs
    j = 4
    n_in, j = read_varint(tx, j)
    ins = []
    for _ in range(n_in):
        e, i = read_map(raw, i)
        ins.append(e)
    return g, ins, raw[i:]

def is_ae(key):
    if not key or key[0] != PROPRIETARY: return False
    ident_len, j = read_varint(key, 1)
    return key[j:j+ident_len] == AE_PREFIX

def base_fingerprint(raw, drop_sigs):
    """Everything except ae records (and optionally partial sigs), order preserved."""
    g, ins, tail = split_maps(raw)
    h = hashlib.sha256()
    for k, v in g:
        h.update(bytes([len(k)])); h.update(k); h.update(len(v).to_bytes(4,'big')); h.update(v)
    for entries in ins:
        for k, v in entries:
            if is_ae(k): continue
            if drop_sigs and k and k[0] == 0x02: continue
            h.update(bytes([len(k)])); h.update(k); h.update(len(v).to_bytes(4,'big')); h.update(v)
    h.update(tail)
    return h.hexdigest()

stages = {
    "M1 (coordinator out)": base64.b64decode(const("ROUND1_OUT")),
    "M2 (device reply)":    base64.b64decode(const("ROUND1_REPLY")),
    "M4 (device reply)":    base64.b64decode(const("ROUND2_REPLY")),
}

print("base fingerprint, ae records removed, partial signatures KEPT:")
fps = {}
for name, raw in stages.items():
    fp = base_fingerprint(raw, drop_sigs=False)
    fps[name] = fp
    print(f"  {name:22} {fp[:16]}  ({len(raw)} bytes total)")
print("  identical across all three:", len(set(fps.values())) == 1)

print("\nbase fingerprint, ae records AND partial signatures removed:")
fps2 = {}
for name, raw in stages.items():
    fp = base_fingerprint(raw, drop_sigs=True)
    fps2[name] = fp
    print(f"  {name:22} {fp[:16]}")
same = len(set(fps2.values())) == 1
print("  identical across all three:", same)

print("\nkey ORDER within input 0, per stage:")
for name, raw in stages.items():
    _, ins, _ = split_maps(raw)
    order = []
    for k, v in ins[0]:
        if is_ae(k):
            ident_len, j = read_varint(k, 1)
            order.append(f"ae[{k[j+ident_len]}]")
        else:
            order.append(f"0x{k[0]:02x}")
    print(f"  {name:22} {' '.join(order)}")
