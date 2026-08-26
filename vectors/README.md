# Anti-exfil vectors

Shared artifacts for cross-implementation conformance of interactive ECDSA
sign-to-contract anti-exfil. Published so another implementation can run them
rather than take this one's word for anything.

Profile: in-PSBT, BIP-174 proprietary records, identifier `ae`, keyed per signer
pubkey. See the transport profiles comparison in the review repository; no
carriage is normative.

## What is here

| file | what it is |
|---|---|
| `lark-ae-ecdsa-crypto-v1.json` | 18 crypto-layer cases plus 4 tweak boundary cases. Transport-neutral: a signature, an opening, entropy, and a verdict |
| `check_vectors.py` | independent checker for the above, sharing no code with the implementation the vectors came from |
| `lark-ae-semantic-transcript-v1.json` | the recorded testnet4 ceremony described semantically: session binding, ordered slots, per-stage commitments, openings, entropy and signature |
| `transcript/` | the four stage artifacts of that ceremony, base64 PSBTs |
| `verify_transcript.py` | checks the transcript is internally consistent and that the recorded signature satisfies it |
| `lark-ae-negatives-v1.json` | seven adversarial cases with expected reason classes |
| `negatives/` | the mutated responses those cases refer to |
| `build_semantic_mapping.py` | regenerates the semantic transcript from the fixtures |
| `build_negatives.py` | regenerates the adversarial cases from the captured transcript |
| `base_identity.py` | measures whether the in-PSBT base survives a device round trip byte-identically |

## Running them

```
python3 vectors/check_vectors.py vectors/lark-ae-ecdsa-crypto-v1.json
python3 vectors/verify_transcript.py
python3 vectors/base_identity.py
```

Regenerating (the transcript capture needs a build, the rest do not):

```
./gradlew :lark:testClasses
java -cp CLASSPATH   # test classes, main classes, and drongo com.sparrowwallet.lark.AntiExfilVectorExport
java -cp CLASSPATH   # test classes, main classes, and drongo com.sparrowwallet.lark.AntiExfilTranscriptExport
python3 vectors/build_semantic_mapping.py
python3 vectors/build_negatives.py
```

The adversarial cases run against this coordinator via
`./gradlew :lark:test --tests '*AntiExfilNegativesTest'`, which prints what
happens to each rather than asserting a uniform rejection.

## What the crypto vectors cannot do

They carry no pubkey and no message hash. They came from libwally's anti-exfil
primitives rather than from a signed transaction, so the key and message behind
each signature are not recoverable, and `expected_ecdsa` and `expected_combined`
are null throughout. `check_vectors.py` handles both shapes: where a case does
carry a pubkey and message hash it verifies ordinary ECDSA too, and requires the
combined verdict to equal the conjunction of the two.

## Known gaps in this implementation

Stated here rather than left for someone else to find.

- **No response allowlist.** The coordinator pins the non-witness txid of the
  unsigned transaction at every hop and consumes the partial signature mapped to
  the expected pubkey, but it does not prove the returned base is identical to
  the frozen original, and it does not reject unrequested fields. The
  `unknown-ae-subtype` case documents this directly: a proprietary record the
  coordinator never asked for is carried through and ignored rather than
  refused.
- **Binding is weaker than a frozen-context digest.** Txid pinning does not
  cover fields the txid excludes. A transport-neutral signing-context digest is
  proposed instead and is not yet implemented anywhere.
- **No error taxonomy.** Failures raise exceptions with prose messages. The
  `expected_reason` values in the negatives manifest refer to classes proposed
  in the shared state machine draft, which are not yet agreed or emitted.
- **Multisig and mixed coverage are untested.** The code is keyed per input and
  per pubkey, so it should handle both, but no fixture exercises them and
  "should" is not evidence.
- **Coordinator sessions do not survive restart.** In-memory, capped at 16, lost
  on restart. The agreed direction is to fail closed before revealing entropy
  when secure persistence is unavailable.

## What this coordinator does with each case

Measured, not predicted. Two of the seven are accepted.

| case | outcome | caught by |
|---|---|---|
| changed-signing-context | rejected | txid pinning |
| cross-key-signature | rejected | no signature under the expected pubkey |
| unrelated-valid-signature | rejected | exact-signature binding |
| duplicate-ae-record | rejected | PSBT parser, on duplicate keys |
| mutation-outside-allowlist | rejected | incidentally, see below |
| stripped-ae-records | accepted | profile difference, see below |
| unknown-ae-subtype | accepted | the allowlist gap |

Two of these rejections deserve qualifying rather than claiming.

`duplicate-ae-record` is refused by the PSBT parser before the anti-exfil layer
sees it, because BIP-174 forbids duplicate keys. That is a correct outcome and
not a protocol check. An implementation whose parser is more permissive would
need its own check here, so the shared state machine should require one rather
than assume the format enforces it.

`mutation-outside-allowlist` changes the sighash type, and this coordinator
refuses it only because the signature was made over the original sighash and no
longer verifies. Nothing rejected the mutation as such. A mutation to a field
the sighash does not cover would still pass. The case therefore does not show
an allowlist exists here; it shows that this particular mutation happens to
collide with a check that does.

## One case that is a profile difference, not a failure

`stripped-ae-records` removes every anti-exfil record from the response.
This coordinator accepts it, and that is not obviously wrong: verification uses
only state retained from earlier stages, never fields echoed back by the signer,
so a response stripped of them is verified against the same values regardless.
For a detached profile the case does not arise at all, since responses carry no
PSBT.

It is included because a coordinator that *did* rely on echoed fields would have
to reject it, and the shared state machine should say which behaviour is
required rather than leaving it to each implementation.
