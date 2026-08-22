package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.TransactionSignature;

import java.util.*;

/**
 * Orchestrates the two-round anti-exfil sign_psbt exchange with a Jade
 * (per ae-psbt-spec.md). Transport-agnostic: caller performs delivery
 * (JadeDevice.signTransaction over USB, or QR display/scan) between phases.
 *
 * Usage:
 *   AntiExfilSession s = new AntiExfilSession(psbtBytes, signerPubkeysByInput);
 *   byte[] round1 = s.buildRound1();          // -> deliver to Jade
 *   s.acceptRound1Reply(jadeReply1);          // commitments in, entropy added
 *   byte[] round2 = s.buildRound2();          // -> deliver to Jade
 *   s.verifyAndExtract(jadeReply2);           // throws on ANY verification failure
 */
public class AntiExfilSession {

    private static final byte PROPRIETARY = (byte)0xFC;
    private static final byte[] ID = {'a','e'};
    private static final byte SUB_HOST_COMMITMENT = 0x00;
    private static final byte SUB_SIGNER_COMMITMENT = 0x01;
    private static final byte SUB_HOST_ENTROPY = 0x02;

    /** input index -> signer pubkey (33) -> host entropy (32) */
    private final Map<Integer, Map<ByteKey, byte[]>> entropyByInput = new HashMap<>();
    /** input index -> signer pubkey -> signer commitment R0 (33) */
    private final Map<Integer, Map<ByteKey, byte[]>> commitmentByInput = new HashMap<>();
    private final byte[] originalPsbt;
    private final Map<Integer, List<byte[]>> signersByInput;

    public AntiExfilSession(byte[] psbtBytes, Map<Integer, List<byte[]>> signerPubkeysByInput) {
        this.originalPsbt = psbtBytes.clone();
        this.signersByInput = signerPubkeysByInput;
    }

    /**
     * Round 1 PSBT: host commitments added, no entropy.
     *
     * Entropy is generated once per (input, pubkey) and REUSED if this is called
     * again for the same session. See acceptRound1Reply for why: re-randomising on
     * a retry would hand a misbehaving device a fresh attempt at the nonce.
     */
    public byte[] buildRound1() throws Exception {
        PSBT psbt = new PSBT(originalPsbt);
        for (Map.Entry<Integer, List<byte[]>> e : signersByInput.entrySet()) {
            PSBTInput input = psbt.getPsbtInputs().get(e.getKey());
            Map<ByteKey, byte[]> perKey = entropyByInput.computeIfAbsent(e.getKey(), k -> new HashMap<>());
            for (byte[] pubkey : e.getValue()) {
                byte[] entropy = perKey.computeIfAbsent(new ByteKey(pubkey),
                        k -> AntiExfilVerifier.generateHostEntropy());
                putProprietary(input, SUB_HOST_COMMITMENT, pubkey, AntiExfilVerifier.hostCommitment(entropy));
            }
        }
        return psbt.serialize();
    }

    /**
     * Parse Jade's round-1 reply, capture signer commitments. Throws if any are missing.
     *
     * If a commitment was already captured for this key in an earlier attempt, the
     * device MUST return the same one. A device is free to fail a round at will,
     * and each failure looks to the user like a flaky scan; if every retry drew
     * fresh host entropy and accepted a fresh R0, the device could abort until it
     * got a nonce it liked, grinding out a covert channel one abandoned attempt at
     * a time. Pinning entropy per session and requiring R0 to be stable removes
     * that. (libwally's anti-exfil documentation gives the same guidance: restart
     * only with the same host entropy, and check the device proposes the same R0.)
     */
    public void acceptRound1Reply(byte[] psbtBytes) throws Exception {
        PSBT psbt = new PSBT(psbtBytes);
        requireSameTransaction(psbt, "round 1 reply");
        for (Map.Entry<Integer, Map<ByteKey, byte[]>> e : entropyByInput.entrySet()) {
            PSBTInput input = psbt.getPsbtInputs().get(e.getKey());
            Map<ByteKey, byte[]> perKey = commitmentByInput.computeIfAbsent(e.getKey(), k -> new HashMap<>());
            for (ByteKey pubkey : e.getValue().keySet()) {
                byte[] commitment = findProprietary(input, SUB_SIGNER_COMMITMENT, pubkey.bytes);
                if (commitment == null || commitment.length != 33) {
                    throw new IllegalStateException("Device did not return anti-exfil commitment for input "
                            + e.getKey() + " - device may not support anti-exfil, or is misbehaving");
                }
                byte[] previous = perKey.get(pubkey);
                if (previous != null && !Arrays.equals(previous, commitment)) {
                    throw new SecurityException("Device returned a different anti-exfil commitment on retry for input "
                            + e.getKey() + ". A device that varies its nonce commitment across attempts can grind "
                            + "a covert channel by aborting. Do not proceed. Treat this device as compromised.");
                }
                perKey.put(pubkey, commitment);
            }
            if (input.getPartialSignatures() != null && !input.getPartialSignatures().isEmpty()) {
                throw new IllegalStateException(
                        "Device signed during commitment round - anti-exfil protocol violation");
            }
        }
    }

    /**
     * Round 2 PSBT: re-sends host commitment + signer commitment + revealed
     * entropy for every input.
     *
     * The host commitment is re-sent because the signing device is stateless
     * across rounds: it re-derives tagged_hash("s2c/ecdsa/data", entropy) from
     * the revealed entropy and rejects the input if it does not match, which is
     * what stops the host from changing its mind about the entropy after seeing
     * the signer commitment.
     *
     * The signer commitment is re-sent for spec conformance only - the device
     * ignores it. R0 is derived deterministically from (privkey, sighash,
     * host_commitment), so the device reproduces the same nonce in round 2
     * without being told what it committed to. That binding is enforced
     * host-side instead, in verifyAndExtract() below, which checks the returned
     * signature against the R0 captured in round 1.
     */
    public byte[] buildRound2() throws Exception {
        PSBT psbt = new PSBT(originalPsbt);
        for (Map.Entry<Integer, Map<ByteKey, byte[]>> e : entropyByInput.entrySet()) {
            PSBTInput input = psbt.getPsbtInputs().get(e.getKey());
            for (Map.Entry<ByteKey, byte[]> k : e.getValue().entrySet()) {
                byte[] pubkey = k.getKey().bytes;
                putProprietary(input, SUB_HOST_COMMITMENT, pubkey, AntiExfilVerifier.hostCommitment(k.getValue()));
                putProprietary(input, SUB_SIGNER_COMMITMENT, pubkey, commitmentByInput.get(e.getKey()).get(k.getKey()));
                putProprietary(input, SUB_HOST_ENTROPY, pubkey, k.getValue());
            }
        }
        return psbt.serialize();
    }

    /**
     * Verify every expected signature incorporates our entropy.
     * @throws SecurityException on ANY failure - the caller MUST discard the
     *         PSBT, refuse broadcast, and warn the user prominently.
     */
    public PSBT verifyAndExtract(byte[] signedPsbtBytes) throws Exception {
        PSBT psbt = new PSBT(signedPsbtBytes);
        requireSameTransaction(psbt, "signed reply");
        for (Map.Entry<Integer, Map<ByteKey, byte[]>> e : entropyByInput.entrySet()) {
            PSBTInput input = psbt.getPsbtInputs().get(e.getKey());
            for (Map.Entry<ByteKey, byte[]> k : e.getValue().entrySet()) {
                byte[] sig = getPartialSignature(input, k.getKey().bytes);
                byte[] commitment = commitmentByInput.get(e.getKey()).get(k.getKey());
                if (sig == null) {
                    throw new SecurityException("Missing signature for anti-exfil input " + e.getKey());
                }
                if (!AntiExfilVerifier.verify(sig, commitment, k.getValue())) {
                    throw new SecurityException("ANTI-EXFIL VERIFICATION FAILED on input " + e.getKey()
                            + ". The signing device may be leaking key material through signature nonces. "
                            + "Do not broadcast. Treat this device as compromised.");
                }
                // Verified: remove the ae proprietary fields so the returned PSBT
                // is clean for broadcast (no anti-exfil scaffolding left behind).
                stripProprietary(input, k.getKey().bytes);
            }
        }
        return psbt;
    }

    /**
     * Every reply must be for the transaction we sent.
     *
     * The sign-to-contract check proves the device folded our entropy into its
     * nonce, but it is computed over the sighash the device itself used - it says
     * nothing about WHICH transaction was signed. Without this, a device could
     * return a correctly formed commitment and signature for a different
     * transaction and pass verification. Pin the txid at every hop instead.
     */
    private void requireSameTransaction(PSBT reply, String stage) throws Exception {
        if(!new PSBT(originalPsbt).matches(reply)) {
            throw new SecurityException("Device returned a different transaction in the " + stage
                    + " - do not broadcast. Treat this device as compromised.");
        }
    }

    // --- proprietary field plumbing (raw key: FC | 02 'a' 'e' | subtype | pubkey33) ---

    static byte[] rawKey(byte subtype, byte[] pubkey) {
        byte[] key = new byte[1 + 1 + ID.length + 1 + 33];
        int i = 0;
        key[i++] = PROPRIETARY;
        key[i++] = (byte) ID.length;
        System.arraycopy(ID, 0, key, i, ID.length); i += ID.length;
        key[i++] = subtype;
        System.arraycopy(pubkey, 0, key, i, 33);
        return key;
    }

    /* drongo stores proprietary entries in Map<String,String> (hex->hex), keyed by
     * the PSBT key data AFTER the 0xFC keytype byte (PSBTEntry.getKeyData()).
     * So the drongo key is rawKey(...) minus its first byte. */
    private static String drongoKey(byte subtype, byte[] pubkey) {
        byte[] raw = rawKey(subtype, pubkey);
        return Utils.bytesToHex(Arrays.copyOfRange(raw, 1, raw.length));
    }
    private static void putProprietary(PSBTInput input, byte subtype, byte[] pubkey, byte[] value) {
        input.getProprietary().put(drongoKey(subtype, pubkey), Utils.bytesToHex(value));
    }
    private static byte[] findProprietary(PSBTInput input, byte subtype, byte[] pubkey) {
        String hex = input.getProprietary().get(drongoKey(subtype, pubkey));
        return hex == null ? null : Utils.hexToBytes(hex);
    }
    private static void stripProprietary(PSBTInput input, byte[] pubkey) {
        for (byte st : new byte[]{SUB_HOST_COMMITMENT, SUB_SIGNER_COMMITMENT, SUB_HOST_ENTROPY}) {
            input.getProprietary().remove(drongoKey(st, pubkey));
        }
    }
    private static byte[] getPartialSignature(PSBTInput input, byte[] pubkey) {
        TransactionSignature sig = input.getPartialSignature(ECKey.fromPublicOnly(pubkey));
        return sig == null ? null : sig.encodeToBitcoin();
    }

    /** byte[] map key wrapper */
    static final class ByteKey {
        final byte[] bytes;
        ByteKey(byte[] b) { this.bytes = b.clone(); }
        @Override public boolean equals(Object o) { return o instanceof ByteKey bk && Arrays.equals(bytes, bk.bytes); }
        @Override public int hashCode() { return Arrays.hashCode(bytes); }
    }
}
