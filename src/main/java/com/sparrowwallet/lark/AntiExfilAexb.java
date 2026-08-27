package com.sparrowwallet.lark;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/**
 * Codec for the AEXB v1 detached anti-exfil envelope, as implemented by Kern
 * (FractalEncrypt/Kern, main/qr/anti_exfil_aexb.c).
 *
 * This is the second carriage lark understands. The in-PSBT profile writes
 * anti-exfil records into the PSBT as BIP-174 proprietary 0xFC entries under
 * identifier "ae"; this profile leaves the PSBT untouched and carries the same
 * information in a separate fixed-layout binary message alongside it.
 *
 * The semantics are identical either way - the same four stages, the same
 * per-slot fields, the same sign-to-contract relation - so this class does no
 * verification. It converts between bytes and slot records and nothing more.
 * AntiExfilVerifier remains the only place the crypto is checked.
 *
 * Layout, all integers big-endian:
 *
 *   header, 78 bytes
 *     0   magic "AEXB"                4
 *     4   version                     1
 *     5   network                     1
 *     6   stage                       1   1..4
 *     7   flags                       1
 *     8   payload_len                 4   slot_count * recordLength(stage)
 *     12  session_id                 32
 *     44  psbt_digest                32
 *     76  slot_count                  2
 *
 *   slot record, recordLength(stage) bytes
 *     +0    input_index               4
 *     +4    sighash_type              4
 *     +8    signer_pubkey            33
 *     +41   message_hash             32
 *     +73   host_commitment          32
 *     +105  opening                  33   stage >= 2
 *     +138  host_reveal              32   stage 3 only
 *     +138  signature                64   stage 4 only
 *
 * Record lengths are therefore 105, 138, 170 and 202 for stages 1 to 4.
 *
 * Verified byte-identical against Kern's published multisig fixture
 * (kern-multisig-two-signatures-per-input-v1.json) at both stage 3 and stage 4:
 * decoding and re-encoding reproduces the original bytes exactly.
 */
public final class AntiExfilAexb {

    private static final byte[] MAGIC = {'A', 'E', 'X', 'B'};

    public static final int HEADER_LEN = 78;
    public static final int MAX_LEN = 65536;
    public static final int MAX_SLOTS = 128;
    public static final int MAX_SLOTS_PER_INPUT = 16;
    public static final int PROTOCOL_VERSION = 1;
    public static final int SIGHASH_ALL = 1;

    /** secp256k1 group order, and half of it, for the low-S check. */
    private static final byte[] CURVE_ORDER = HexFormat.of().parseHex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static final byte[] CURVE_HALF_ORDER = HexFormat.of().parseHex(
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");

    public static final int SESSION_ID_LEN = 32;
    public static final int PSBT_DIGEST_LEN = 32;
    public static final int PUBKEY_LEN = 33;
    public static final int MESSAGE_HASH_LEN = 32;
    public static final int HOST_COMMITMENT_LEN = 32;
    public static final int OPENING_LEN = 33;
    public static final int HOST_REVEAL_LEN = 32;
    public static final int SIGNATURE_LEN = 64;

    public static final int STAGE_HOST_COMMIT = 1;
    public static final int STAGE_SIGNER_OPENINGS = 2;
    public static final int STAGE_HOST_REVEAL = 3;
    public static final int STAGE_SIGNER_SIGNATURES = 4;

    public static final int NETWORK_MAINNET = 0;
    public static final int NETWORK_TESTNET3 = 1;
    public static final int NETWORK_REGTEST = 2;
    public static final int NETWORK_SIGNET = 3;
    public static final int NETWORK_TESTNET4 = 4;

    private AntiExfilAexb() {
    }

    /**
     * Bytes on the wire for one slot at a given stage. Fixed per stage, which
     * is what lets the decoder assert that the payload is consumed exactly
     * rather than trusting a length field.
     */
    public static int recordLength(int stage) {
        switch(stage) {
            case STAGE_HOST_COMMIT: return 105;
            case STAGE_SIGNER_OPENINGS: return 138;
            case STAGE_HOST_REVEAL: return 170;
            case STAGE_SIGNER_SIGNATURES: return 202;
            default: throw new IllegalArgumentException("Unknown anti-exfil stage: " + stage);
        }
    }

    public static int encodedLength(int stage, int slotCount) {
        return HEADER_LEN + slotCount * recordLength(stage);
    }

    /**
     * One (input, signer key) slot. Fields not carried at a given stage are
     * null; the encoder rejects a slot missing a field its stage requires
     * rather than padding with zeroes, so an incomplete slot cannot be encoded
     * into something that decodes as well-formed.
     */
    public static final class Slot {
        public final long inputIndex;
        public final long sighashType;
        public final byte[] signerPubkey;
        public final byte[] messageHash;
        public final byte[] hostCommitment;
        public final byte[] opening;
        public final byte[] hostReveal;
        public final byte[] signature;

        public Slot(long inputIndex, long sighashType, byte[] signerPubkey, byte[] messageHash,
                    byte[] hostCommitment, byte[] opening, byte[] hostReveal, byte[] signature) {
            this.inputIndex = inputIndex;
            this.sighashType = sighashType;
            this.signerPubkey = copy(signerPubkey);
            this.messageHash = copy(messageHash);
            this.hostCommitment = copy(hostCommitment);
            this.opening = copy(opening);
            this.hostReveal = copy(hostReveal);
            this.signature = copy(signature);
        }

        private static byte[] copy(byte[] b) {
            return b == null ? null : b.clone();
        }
    }

    /** A decoded AEXB message: header fields plus its slots. */
    public static final class Message {
        public final int version;
        public final int network;
        public final int stage;
        public final int flags;
        public final byte[] sessionId;
        public final byte[] psbtDigest;
        public final List<Slot> slots;

        public Message(int version, int network, int stage, int flags,
                       byte[] sessionId, byte[] psbtDigest, List<Slot> slots) {
            this.version = version;
            this.network = network;
            this.stage = stage;
            this.flags = flags;
            this.sessionId = sessionId.clone();
            this.psbtDigest = psbtDigest.clone();
            this.slots = List.copyOf(slots);
        }
    }

    public static byte[] encode(Message message) {
        if(message == null) {
            throw new IllegalArgumentException("Message is null");
        }
        validate(message);
        int stage = message.stage;
        int recordLen = recordLength(stage);
        int slotCount = message.slots.size();
        if(slotCount == 0 || slotCount > MAX_SLOTS) {
            throw new IllegalArgumentException("Slot count must be 1.." + MAX_SLOTS + ", got " + slotCount);
        }
        requireLength(message.sessionId, SESSION_ID_LEN, "session id");
        requireLength(message.psbtDigest, PSBT_DIGEST_LEN, "psbt digest");

        int payloadLen = slotCount * recordLen;
        int total = HEADER_LEN + payloadLen;
        if(total > MAX_LEN) {
            throw new IllegalArgumentException("Encoded message would be " + total
                    + " bytes, over the " + MAX_LEN + " byte limit");
        }

        byte[] out = new byte[total];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[4] = (byte)message.version;
        out[5] = (byte)message.network;
        out[6] = (byte)stage;
        out[7] = (byte)message.flags;
        putU32(out, 8, payloadLen);
        System.arraycopy(message.sessionId, 0, out, 12, SESSION_ID_LEN);
        System.arraycopy(message.psbtDigest, 0, out, 44, PSBT_DIGEST_LEN);
        putU16(out, 76, slotCount);

        int offset = HEADER_LEN;
        for(Slot slot : message.slots) {
            putU32(out, offset, slot.inputIndex);
            putU32(out, offset + 4, slot.sighashType);
            put(out, offset + 8, require(slot.signerPubkey, PUBKEY_LEN, "signer pubkey"));
            put(out, offset + 41, require(slot.messageHash, MESSAGE_HASH_LEN, "message hash"));
            put(out, offset + 73, require(slot.hostCommitment, HOST_COMMITMENT_LEN, "host commitment"));
            if(stage >= STAGE_SIGNER_OPENINGS) {
                put(out, offset + 105, require(slot.opening, OPENING_LEN, "opening"));
            }
            if(stage == STAGE_HOST_REVEAL) {
                put(out, offset + 138, require(slot.hostReveal, HOST_REVEAL_LEN, "host reveal"));
            }
            if(stage == STAGE_SIGNER_SIGNATURES) {
                put(out, offset + 138, require(slot.signature, SIGNATURE_LEN, "signature"));
            }
            offset += recordLen;
        }
        return out;
    }

    /**
     * Decode, rejecting anything that does not fit the layout exactly.
     *
     * The payload length field and the slot count are cross-checked against
     * each other and against the actual buffer length, so a message cannot
     * claim one shape and carry another - which is the check that stops a
     * truncated or padded envelope being read as a shorter valid one.
     */
    public static Message decode(byte[] encoded) {
        if(encoded == null || encoded.length < HEADER_LEN) {
            throw new IllegalArgumentException("Buffer shorter than the "
                    + HEADER_LEN + " byte AEXB header");
        }
        if(encoded.length > MAX_LEN) {
            throw new IllegalArgumentException("Buffer over the " + MAX_LEN + " byte limit");
        }
        if(!Arrays.equals(Arrays.copyOfRange(encoded, 0, 4), MAGIC)) {
            throw new IllegalArgumentException("Not an AEXB message - bad magic");
        }

        int version = encoded[4] & 0xFF;
        int network = encoded[5] & 0xFF;
        int stage = encoded[6] & 0xFF;
        int flags = encoded[7] & 0xFF;
        if(stage < STAGE_HOST_COMMIT || stage > STAGE_SIGNER_SIGNATURES) {
            throw new IllegalArgumentException("Unknown anti-exfil stage: " + stage);
        }
        int recordLen = recordLength(stage);
        long payloadLen = getU32(encoded, 8);
        int slotCount = getU16(encoded, 76);

        if(slotCount == 0 || slotCount > MAX_SLOTS) {
            throw new IllegalArgumentException("Slot count must be 1.." + MAX_SLOTS + ", got " + slotCount);
        }
        if(payloadLen != (long)slotCount * recordLen) {
            throw new IllegalArgumentException("Payload length field " + payloadLen
                    + " does not match " + slotCount + " slots of " + recordLen + " bytes");
        }
        if(encoded.length != HEADER_LEN + payloadLen) {
            throw new IllegalArgumentException("Buffer is " + encoded.length + " bytes, layout needs "
                    + (HEADER_LEN + payloadLen));
        }

        byte[] sessionId = Arrays.copyOfRange(encoded, 12, 12 + SESSION_ID_LEN);
        byte[] psbtDigest = Arrays.copyOfRange(encoded, 44, 44 + PSBT_DIGEST_LEN);

        List<Slot> slots = new ArrayList<>(slotCount);
        int offset = HEADER_LEN;
        for(int i = 0; i < slotCount; i++) {
            long inputIndex = getU32(encoded, offset);
            long sighashType = getU32(encoded, offset + 4);
            byte[] pubkey = Arrays.copyOfRange(encoded, offset + 8, offset + 41);
            byte[] messageHash = Arrays.copyOfRange(encoded, offset + 41, offset + 73);
            byte[] hostCommitment = Arrays.copyOfRange(encoded, offset + 73, offset + 105);
            byte[] opening = stage >= STAGE_SIGNER_OPENINGS
                    ? Arrays.copyOfRange(encoded, offset + 105, offset + 138) : null;
            byte[] hostReveal = stage == STAGE_HOST_REVEAL
                    ? Arrays.copyOfRange(encoded, offset + 138, offset + 170) : null;
            byte[] signature = stage == STAGE_SIGNER_SIGNATURES
                    ? Arrays.copyOfRange(encoded, offset + 138, offset + 202) : null;
            slots.add(new Slot(inputIndex, sighashType, pubkey, messageHash,
                    hostCommitment, opening, hostReveal, signature));
            offset += recordLen;
        }
        Message message = new Message(version, network, stage, flags, sessionId, psbtDigest, slots);
        validate(message);
        return message;
    }

    /**
     * Convert a compact 64-byte signature to canonical DER.
     *
     * The two carriages disagree on signature encoding: BIP-174 partial
     * signatures are DER, so the in-PSBT profile carries DER, while AEXB
     * carries compact r||s. AntiExfilVerifier.verify() takes DER, so a slot
     * from this profile must be converted before it can be checked.
     *
     * The conversion is deliberately one-directional and canonical. Compact
     * encoding has exactly one representation per (r, s), whereas DER admits
     * several, and lark's verifier rejects all but the canonical one precisely
     * because that freedom is a covert channel. Re-encoding from compact
     * therefore produces a signature with the channel closed by construction,
     * rather than one that has to be policed.
     *
     * Low-S is NOT enforced here. It is a property of s rather than of the
     * encoding, and the verifier already rejects a high-S signature; silently
     * normalising it here would convert a signature that must be refused into
     * one that passes.
     *
     * No sighash byte is appended. That belongs to the PSBT representation, not
     * to the signature itself, and the caller adding it knows which sighash
     * type the slot carries.
     */
    public static byte[] toDerSignature(byte[] compact) {
        requireLength(compact, SIGNATURE_LEN, "compact signature");
        byte[] r = trimScalar(Arrays.copyOfRange(compact, 0, 32));
        byte[] s = trimScalar(Arrays.copyOfRange(compact, 32, 64));
        int bodyLen = 2 + r.length + 2 + s.length;
        byte[] der = new byte[2 + bodyLen];
        der[0] = 0x30;
        der[1] = (byte)bodyLen;
        der[2] = 0x02;
        der[3] = (byte)r.length;
        System.arraycopy(r, 0, der, 4, r.length);
        der[4 + r.length] = 0x02;
        der[5 + r.length] = (byte)s.length;
        System.arraycopy(s, 0, der, 6 + r.length, s.length);
        return der;
    }

    /**
     * DER integers are signed and minimally encoded: strip leading zero bytes,
     * then prepend one back if the top bit would otherwise read as negative.
     */
    private static byte[] trimScalar(byte[] scalar) {
        int start = 0;
        while(start < scalar.length - 1 && scalar[start] == 0) {
            start++;
        }
        byte[] trimmed = Arrays.copyOfRange(scalar, start, scalar.length);
        if((trimmed[0] & 0x80) != 0) {
            byte[] padded = new byte[trimmed.length + 1];
            System.arraycopy(trimmed, 0, padded, 1, trimmed.length);
            return padded;
        }
        return trimmed;
    }

    /**
     * The rules Kern enforces in anti_exfil_semantic_validate(), applied on
     * both encode and decode as Kern does.
     *
     * A decoder more permissive than the peer's encoder is an interop hazard
     * rather than a kindness: lark would accept an envelope Kern considers
     * malformed, and the disagreement would surface later as an unexplained
     * rejection on the device rather than here. Several of these are also
     * security properties in their own right - slot ordering, commitment
     * uniqueness and low-S all close something.
     *
     * Two of Kern's checks are deliberately not made here. Public keys and
     * openings are checked for a valid compressed prefix but not for being on
     * the curve, and message hashes are not related to the transaction. Both
     * need context this class does not have - an EC implementation and the
     * PSBT - and both are already enforced downstream by AntiExfilVerifier and
     * by the session. Doing them here would duplicate that at the cost of
     * making the codec depend on the crypto layer.
     */
    public static void validate(Message message) {
        if(message == null) {
            throw new IllegalArgumentException("Message is null");
        }
        if(message.version != PROTOCOL_VERSION) {
            throw new IllegalArgumentException("Unsupported anti-exfil protocol version: "
                    + message.version);
        }
        if(message.network < NETWORK_MAINNET || message.network > NETWORK_TESTNET4) {
            throw new IllegalArgumentException("Unknown network: " + message.network);
        }
        if(message.flags != 0) {
            throw new IllegalArgumentException("Reserved flags byte must be zero, got " + message.flags);
        }
        if(message.stage < STAGE_HOST_COMMIT || message.stage > STAGE_SIGNER_SIGNATURES) {
            throw new IllegalArgumentException("Unknown anti-exfil stage: " + message.stage);
        }
        int slotCount = message.slots.size();
        if(slotCount == 0 || slotCount > MAX_SLOTS) {
            throw new IllegalArgumentException("Slot count must be 1.." + MAX_SLOTS + ", got " + slotCount);
        }

        boolean hasOpening = message.stage >= STAGE_SIGNER_OPENINGS;
        boolean hasReveal = message.stage == STAGE_HOST_REVEAL;
        boolean hasSignature = message.stage == STAGE_SIGNER_SIGNATURES;

        int slotsForInput = 0;
        for(int i = 0; i < slotCount; i++) {
            Slot slot = message.slots.get(i);

            if(slot.sighashType != SIGHASH_ALL) {
                throw new IllegalArgumentException("Slot " + i + " sighash type must be SIGHASH_ALL, got "
                        + slot.sighashType);
            }
            requireCompressedPoint(slot.signerPubkey, "signer pubkey", i);
            if(hasOpening) {
                requireCompressedPoint(slot.opening, "opening", i);
            }
            if(hasSignature) {
                requireCanonicalSignature(slot.signature, i);
            }

            // Strictly ascending by (input index, pubkey). This both pins a
            // deterministic slot order across implementations and makes a
            // duplicate slot unrepresentable rather than merely rejected.
            if(i > 0) {
                Slot previous = message.slots.get(i - 1);
                if(compareSlotId(previous, slot) >= 0) {
                    throw new IllegalArgumentException("Slots must be strictly ascending by "
                            + "(input index, signer pubkey); slot " + i + " is out of order or duplicated");
                }
                slotsForInput = previous.inputIndex == slot.inputIndex ? slotsForInput + 1 : 1;
            } else {
                slotsForInput = 1;
            }
            if(slotsForInput > MAX_SLOTS_PER_INPUT) {
                throw new IllegalArgumentException("More than " + MAX_SLOTS_PER_INPUT
                        + " slots on input " + slot.inputIndex);
            }

            // Host commitments and revealed entropy must be independent per
            // slot. A repeat means the host's entropy source is faulty, which
            // silently degrades the protection while still completing.
            for(int j = 0; j < i; j++) {
                Slot other = message.slots.get(j);
                if(Arrays.equals(slot.hostCommitment, other.hostCommitment)) {
                    throw new IllegalArgumentException("Duplicate host commitment at slots "
                            + j + " and " + i + "; host entropy must be independent per slot");
                }
                if(hasReveal && Arrays.equals(slot.hostReveal, other.hostReveal)) {
                    throw new IllegalArgumentException("Duplicate revealed host entropy at slots "
                            + j + " and " + i);
                }
                if(hasOpening && Arrays.equals(slot.signerPubkey, other.signerPubkey)
                        && Arrays.equals(slot.opening, other.opening)) {
                    throw new IllegalArgumentException("Signer reused its nonce commitment "
                            + "for the same key at slots " + j + " and " + i);
                }
            }
        }
    }

    private static int compareSlotId(Slot left, Slot right) {
        if(left.inputIndex != right.inputIndex) {
            return Long.compare(left.inputIndex, right.inputIndex);
        }
        return Arrays.compareUnsigned(left.signerPubkey, right.signerPubkey);
    }

    private static void requireCompressedPoint(byte[] point, String what, int index) {
        if(point == null || point.length != PUBKEY_LEN
                || (point[0] != 0x02 && point[0] != 0x03)) {
            throw new IllegalArgumentException("Slot " + index + " " + what
                    + " is not a compressed secp256k1 point");
        }
    }

    /**
     * Non-zero scalars below the curve order, and low-S.
     *
     * Low-S matters here for the same reason canonical DER matters in the
     * in-PSBT profile: the choice between the low and high form of s is a bit
     * the signing device controls freely, and a device that commits to its
     * nonce honestly can still leak key material one bit per signature through
     * it. Compact encoding removes the DER channel; this removes what is left.
     */
    private static void requireCanonicalSignature(byte[] signature, int index) {
        if(signature == null || signature.length != SIGNATURE_LEN) {
            throw new IllegalArgumentException("Slot " + index + " signature must be "
                    + SIGNATURE_LEN + " bytes");
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        byte[] s = Arrays.copyOfRange(signature, 32, 64);
        if(isZero(r) || Arrays.compareUnsigned(r, CURVE_ORDER) >= 0) {
            throw new IllegalArgumentException("Slot " + index + " signature r is zero or out of range");
        }
        if(isZero(s)) {
            throw new IllegalArgumentException("Slot " + index + " signature s is zero");
        }
        if(Arrays.compareUnsigned(s, CURVE_HALF_ORDER) > 0) {
            throw new IllegalArgumentException("Slot " + index + " signature is not low-S. "
                    + "The choice of s form is a covert channel and must not be left open.");
        }
    }

    private static boolean isZero(byte[] bytes) {
        int aggregate = 0;
        for(byte b : bytes) {
            aggregate |= b;
        }
        return aggregate == 0;
    }

    private static byte[] require(byte[] value, int len, String what) {
        if(value == null) {
            throw new IllegalArgumentException("Slot is missing its " + what
                    + ", which this stage requires");
        }
        return requireLength(value, len, what);
    }

    private static byte[] requireLength(byte[] value, int len, String what) {
        if(value == null || value.length != len) {
            throw new IllegalArgumentException("Field " + what + " must be " + len + " bytes, got "
                    + (value == null ? "null" : value.length + " bytes"));
        }
        return value;
    }

    private static void put(byte[] out, int offset, byte[] value) {
        System.arraycopy(value, 0, out, offset, value.length);
    }

    private static void putU16(byte[] out, int offset, int value) {
        out[offset] = (byte)(value >>> 8);
        out[offset + 1] = (byte)value;
    }

    private static void putU32(byte[] out, int offset, long value) {
        out[offset] = (byte)(value >>> 24);
        out[offset + 1] = (byte)(value >>> 16);
        out[offset + 2] = (byte)(value >>> 8);
        out[offset + 3] = (byte)value;
    }

    private static int getU16(byte[] in, int offset) {
        return ((in[offset] & 0xFF) << 8) | (in[offset + 1] & 0xFF);
    }

    private static long getU32(byte[] in, int offset) {
        return ((long)(in[offset] & 0xFF) << 24)
                | ((long)(in[offset + 1] & 0xFF) << 16)
                | ((long)(in[offset + 2] & 0xFF) << 8)
                | (in[offset + 3] & 0xFF);
    }
}
