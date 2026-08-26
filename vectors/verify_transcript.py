import json, hashlib
P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def inv(a): return pow(a,P-2,P)
def add(p,q):
    if p is None: return q
    if q is None: return p
    if p[0]==q[0] and (p[1]+q[1])%P==0: return None
    l=(3*p[0]*p[0]*inv(2*p[1]))%P if p==q else ((q[1]-p[1])*inv(q[0]-p[0]))%P
    x=(l*l-p[0]-q[0])%P; return (x,(l*(p[0]-x)-p[1])%P)
def mul(k,p=G):
    r=None
    while k:
        if k&1: r=add(r,p)
        p=add(p,p); k>>=1
    return r
def decom(b):
    x=int.from_bytes(b[1:],'big'); y=pow((pow(x,3,P)+7)%P,(P+1)//4,P)
    if (y&1)!=(b[0]==3): y=P-y
    return (x,y)
def th(t,m):
    h=hashlib.sha256(t.encode()).digest(); return hashlib.sha256(h+h+m).digest()

d=json.load(open('vectors/lark-ae-semantic-transcript-v1.json'))
S={s['stage']:s for s in d['stages']}
fails=[]

# 1. binding identical across every stage
bindings={s['stage']:s['binding']['value'] for s in d['stages']}
if len(set(bindings.values()))!=1: fails.append(f"binding differs across stages: {bindings}")
if d['session']['binding'] not in set(bindings.values()): fails.append("session binding not equal to stage bindings")

# 2. M1 carries commitment only, no opening, no signature
m1=S['M1']['slots'][0]
if 'signer_opening' in m1: fails.append("M1 carries an opening")
if 'signature_der' in m1: fails.append("M1 carries a signature")
if 'host_entropy' in m1: fails.append("M1 leaks entropy")

# 3. M2 adds opening, still no signature or entropy
m2=S['M2']['slots'][0]
if 'signature_der' in m2: fails.append("M2 carries a signature (protocol violation)")
if 'host_entropy' in m2: fails.append("M2 leaks entropy before reveal")
if 'signer_opening' not in m2: fails.append("M2 missing opening")

# 4. commitment stable M1 -> M2 -> M3 -> M4
comms={st:S[st]['slots'][0]['host_commitment'] for st in ('M1','M2','M3','M4')}
if len(set(comms.values()))!=1: fails.append(f"host commitment not stable: {comms}")

# 5. opening stable M2 -> M4
if S['M2']['slots'][0]['signer_opening'] != S['M4']['slots'][0]['signer_opening']:
    fails.append("opening changed between M2 and M4")

# 6. revealed entropy really opens the commitment
ent=bytes.fromhex(S['M3']['slots'][0]['host_entropy'])
if th("s2c/ecdsa/data",ent).hex()!=comms['M1']:
    fails.append("revealed entropy does not open the M1 commitment")

# 7. the s2c relation holds on the real signature
op=bytes.fromhex(S['M4']['slots'][0]['signer_opening'])
der=bytes.fromhex(S['M4']['slots'][0]['signature_der'])
t=int.from_bytes(th("s2c/ecdsa/point",op+ent),'big')
R=add(decom(op),mul(t))
rl=der[3]; r=int.from_bytes(der[4:4+rl],'big')
off=4+rl; sl=der[off+1]; s=int.from_bytes(der[off+2:off+2+sl],'big')
if R is None or R[0]%N!=r: fails.append("s2c relation FAILS on the transcript signature")
if s>N//2: fails.append("signature is not low-S")

# 8. slot identity consistent
pks={s['stage']:{sl['signer_pubkey'] for sl in s['slots']} for s in d['stages']}
if len({frozenset(v) for v in pks.values()})!=1: fails.append(f"slot set differs across stages: {pks}")
if S['M4']['slots'][0]['signer_pubkey'] not in d['session']['expected_signers']:
    fails.append("M4 signer not in the declared expected signers")

print("checks: binding stability, stage field discipline, commitment stability,")
print("        opening stability, entropy opens commitment, s2c relation, low-S, slot identity")
print()
if fails:
    print(f"FAILED ({len(fails)}):")
    for f in fails: print("  -", f)
else:
    print("PASS - the published transcript is internally consistent and the")
    print("       recorded hardware signature satisfies it")
