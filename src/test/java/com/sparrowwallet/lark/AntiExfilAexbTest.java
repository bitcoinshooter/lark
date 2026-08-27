package com.sparrowwallet.lark;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Conformance tests for the AEXB detached carriage against Kern's published
 * interoperability fixture.
 *
 * The value of this suite is that the fixture was produced by an independent
 * implementation in C, with no shared code. A byte-identical round trip means
 * lark reads and writes the same format Kern does, rather than a format that
 * merely resembles it - which is the property a cross-implementation test has
 * to establish and a self-generated one cannot.
 *
 * The crypto is checked here too, through AntiExfilVerifier, against slots this
 * codec extracted. That closes the loop: the fields are in the places this
 * codec says they are, and the values in those places satisfy the
 * sign-to-contract relation.
 */
public class AntiExfilAexbTest {

    private static final String FIXTURE = "vectors/kern-multisig-two-signatures-per-input-v1.json";

    /**
     * Read the fixture without a JSON dependency. lark has none on its test
     * classpath, and adding one to read two hex strings and a digest would be a
     * poor trade. The fields are extracted by locating their keys, which is
     * sufficient for a fixture whose shape is fixed and version-controlled.
     */
    private static String field(String json, String key) {
        String needle = "\"" + key + "\"";
        int k = json.indexOf(needle);
        if(k < 0) {
            throw new IllegalStateException("Fixture has no field " + key);
        }
        int colon = json.indexOf(':', k + needle.length());
        int open = json.indexOf('"', colon + 1);
        int close = json.indexOf('"', open + 1);
        return json.substring(open + 1, close);
    }

    private static String fixture() throws IOException {
        Path path = Path.of(FIXTURE);
        if(!Files.exists(path)) {
            throw new IllegalStateException("Missing " + FIXTURE
                    + " - copy it from FractalEncrypt/Kern "
                    + "main/core/test/fixtures/anti_exfil/profile_interop/");
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s.trim());
    }

    @Test
    public void stage3RoundTripsByteIdentical() throws IOException {
        byte[] original = hex(field(fixture(), "message_3_hex"));
        AntiExfilAexb.Message message = AntiExfilAexb.decode(original);

        assertEquals(AntiExfilAexb.STAGE_HOST_REVEAL, message.stage);
        assertEquals(AntiExfilAexb.PROTOCOL_VERSION, message.version);
        assertEquals(AntiExfilAexb.NETWORK_TESTNET4, message.network);
        assertEquals(5, message.slots.size());
        assertEquals(928, original.length);

        assertArrayEquals(original, AntiExfilAexb.encode(message),
                "re-encoding a decoded stage 3 message must reproduce Kern's bytes exactly");
    }

    @Test
    public void stage4RoundTripsByteIdentical() throws IOException {
        byte[] original = hex(field(fixture(), "message_4_hex"));
        AntiExfilAexb.Message message = AntiExfilAexb.decode(original);

        assertEquals(AntiExfilAexb.STAGE_SIGNER_SIGNATURES, message.stage);
        assertEquals(5, message.slots.size());
        assertEquals(1088, original.length);

        assertArrayEquals(original, AntiExfilAexb.encode(message),
                "re-encoding a decoded stage 4 message must reproduce Kern's bytes exactly");
    }

    /**
     * The header digest binds the unsigned transaction by its raw bytes. That
     * is safe for this profile precisely because it never writes into the PSBT:
     * with nothing added, there is no reserialisation for a signer's library to
     * perform differently. The in-PSBT profile cannot bind this way, which is
     * the substance of the option (a) versus option (b) question rather than a
     * matter of preference.
     */
    @Test
    public void headerDigestIsTheUnsignedTransactionDigest() throws IOException {
        String json = fixture();
        AntiExfilAexb.Message message = AntiExfilAexb.decode(hex(field(json, "message_3_hex")));
        assertEquals(field(json, "original_psbt_sha256"),
                HexFormat.of().formatHex(message.psbtDigest));
    }

    /** Both request and response stages carry the same session and digest. */
    @Test
    public void stagesShareSessionAndDigest() throws IOException {
        String json = fixture();
        AntiExfilAexb.Message m3 = AntiExfilAexb.decode(hex(field(json, "message_3_hex")));
        AntiExfilAexb.Message m4 = AntiExfilAexb.decode(hex(field(json, "message_4_hex")));
        assertArrayEquals(m3.sessionId, m4.sessionId);
        assertArrayEquals(m3.psbtDigest, m4.psbtDigest);
    }

    /**
     * Stage 3 carries revealed entropy and no signature; stage 4 the reverse.
     * Asserted rather than assumed, because a codec that returned a zeroed
     * buffer instead of null for an absent field would still round trip.
     */
    @Test
    public void absentFieldsAreNullPerStage() throws IOException {
        String json = fixture();
        for(AntiExfilAexb.Slot slot : AntiExfilAexb.decode(hex(field(json, "message_3_hex"))).slots) {
            assertNotNull(slot.opening);
            assertNotNull(slot.hostReveal);
            assertNull(slot.signature);
        }
        for(AntiExfilAexb.Slot slot : AntiExfilAexb.decode(hex(field(json, "message_4_hex"))).slots) {
            assertNotNull(slot.opening);
            assertNull(slot.hostReveal);
            assertNotNull(slot.signature);
        }
    }

    /**
     * The multisig input carries two protected signatures under different keys.
     * This is the case the in-PSBT profile's exact-signature binding fix was
     * written for, and the reason this fixture is worth importing.
     */
    @Test
    public void multisigInputCarriesTwoSlots() throws IOException {
        List<AntiExfilAexb.Slot> slots =
                AntiExfilAexb.decode(hex(field(fixture(), "message_4_hex"))).slots;
        long shared = slots.stream().filter(s -> s.inputIndex == 2).count();
        assertEquals(2, shared);
        List<byte[]> keys = slots.stream().filter(s -> s.inputIndex == 2)
                .map(s -> s.signerPubkey).toList();
        assertTrue(!Arrays.equals(keys.get(0), keys.get(1)),
                "the two slots on the multisig input must be under different keys");
    }

    /**
     * Every slot's sign-to-contract relation holds, checked with lark's own
     * verifier against fields this codec extracted from Kern's bytes.
     */
    @Test
    public void everySlotVerifiesAgainstLarkVerifier() throws IOException {
        String json = fixture();
        List<AntiExfilAexb.Slot> reveal =
                AntiExfilAexb.decode(hex(field(json, "message_3_hex"))).slots;
        List<AntiExfilAexb.Slot> signed =
                AntiExfilAexb.decode(hex(field(json, "message_4_hex"))).slots;
        assertEquals(reveal.size(), signed.size());

        for(int i = 0; i < signed.size(); i++) {
            AntiExfilAexb.Slot sig = signed.get(i);
            AntiExfilAexb.Slot rev = reveal.get(i);
            assertEquals(sig.inputIndex, rev.inputIndex);
            assertArrayEquals(sig.signerPubkey, rev.signerPubkey);

            assertArrayEquals(sig.hostCommitment,
                    AntiExfilVerifier.hostCommitment(rev.hostReveal),
                    "host commitment must re-derive from the revealed entropy, slot " + i);

            assertTrue(AntiExfilVerifier.verify(
                            AntiExfilAexb.toDerSignature(sig.signature), sig.opening, rev.hostReveal),
                    "sign-to-contract must hold for slot " + i
                            + " on input " + sig.inputIndex);
        }
    }

    /**
     * Cross-key substitution on the multisig input must not verify. Without
     * this, a codec that mixed up which opening belongs to which key would
     * still pass every test above.
     */
    @Test
    public void crossKeySubstitutionDoesNotVerify() throws IOException {
        String json = fixture();
        List<AntiExfilAexb.Slot> reveal =
                AntiExfilAexb.decode(hex(field(json, "message_3_hex"))).slots;
        List<AntiExfilAexb.Slot> signed =
                AntiExfilAexb.decode(hex(field(json, "message_4_hex"))).slots;

        int a = -1, b = -1;
        for(int i = 0; i < signed.size(); i++) {
            if(signed.get(i).inputIndex == 2) {
                if(a < 0) { a = i; } else { b = i; }
            }
        }
        assertTrue(a >= 0 && b >= 0, "fixture must have two slots on input 2");

        assertTrue(!AntiExfilVerifier.verify(AntiExfilAexb.toDerSignature(signed.get(b).signature),
                        signed.get(a).opening, reveal.get(a).hostReveal),
                "slot A's opening and entropy must not be satisfied by slot B's signature");
        assertTrue(!AntiExfilVerifier.verify(AntiExfilAexb.toDerSignature(signed.get(a).signature),
                        signed.get(b).opening, reveal.get(b).hostReveal),
                "slot B's opening and entropy must not be satisfied by slot A's signature");
    }

    /**
     * Kern validates on both encode and decode. A decoder more permissive than
     * the peer's encoder would accept envelopes the device considers malformed,
     * so each rule is exercised against a targeted mutation of a real message.
     */
    @Test
    public void headerRulesAreEnforced() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));

        byte[] wrongVersion = good.clone();
        wrongVersion[4] = 2;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(wrongVersion));

        byte[] unknownNetwork = good.clone();
        unknownNetwork[5] = 9;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(unknownNetwork));

        byte[] flagsSet = good.clone();
        flagsSet[7] = 1;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(flagsSet));
    }

    @Test
    public void slotFieldRulesAreEnforced() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));
        int header = AntiExfilAexb.HEADER_LEN;

        byte[] wrongSighash = good.clone();
        wrongSighash[header + 7] = 2;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(wrongSighash));

        byte[] uncompressedKey = good.clone();
        uncompressedKey[header + 8] = 0x04;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(uncompressedKey));

        byte[] badOpening = good.clone();
        badOpening[header + 105] = 0x05;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(badOpening));
    }

    /**
     * Slot order is strictly ascending by (input index, pubkey), which pins a
     * deterministic order across implementations and makes a duplicate slot
     * unrepresentable rather than merely rejected.
     */
    @Test
    public void slotOrderingIsEnforced() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));
        int header = AntiExfilAexb.HEADER_LEN;
        int record = AntiExfilAexb.recordLength(AntiExfilAexb.STAGE_SIGNER_SIGNATURES);

        byte[] first = Arrays.copyOfRange(good, header, header + record);
        byte[] second = Arrays.copyOfRange(good, header + record, header + 2 * record);

        byte[] swapped = good.clone();
        System.arraycopy(second, 0, swapped, header, record);
        System.arraycopy(first, 0, swapped, header + record, record);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(swapped));

        byte[] duplicated = good.clone();
        System.arraycopy(first, 0, duplicated, header + record, record);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(duplicated));
    }

    /**
     * Host commitments must be independent per slot. A repeat means the host's
     * entropy source is faulty, which degrades the protection while still
     * letting the exchange complete and report success - the same property
     * AntiExfilSession checks before emitting round 1.
     */
    @Test
    public void duplicateHostCommitmentIsRejected() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));
        int header = AntiExfilAexb.HEADER_LEN;
        int record = AntiExfilAexb.recordLength(AntiExfilAexb.STAGE_SIGNER_SIGNATURES);

        byte[] repeated = good.clone();
        System.arraycopy(good, header + 73, repeated, header + record + 73, 32);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(repeated));
    }

    /**
     * Low-S, for the same reason the in-PSBT profile requires canonical DER:
     * the choice between the low and high form of s is a bit the device
     * controls freely, and a device committing to its nonce honestly can still
     * leak key material through it.
     */
    @Test
    public void highSSignatureIsRejected() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));
        int sOffset = AntiExfilAexb.HEADER_LEN + 138 + 32;

        BigInteger order = new BigInteger(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        BigInteger low = new BigInteger(1, Arrays.copyOfRange(good, sOffset, sOffset + 32));
        byte[] high = order.subtract(low).toByteArray();

        byte[] flipped = good.clone();
        byte[] padded = new byte[32];
        int copy = Math.min(32, high.length);
        System.arraycopy(high, high.length - copy, padded, 32 - copy, copy);
        System.arraycopy(padded, 0, flipped, sOffset, 32);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(flipped));

        byte[] zeroR = good.clone();
        Arrays.fill(zeroR, AntiExfilAexb.HEADER_LEN + 138, AntiExfilAexb.HEADER_LEN + 138 + 32, (byte)0);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(zeroR));
    }

    @Test
    public void malformedEnvelopesAreRejected() throws IOException {
        byte[] good = hex(field(fixture(), "message_4_hex"));

        byte[] badMagic = good.clone();
        badMagic[0] = 'X';
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(badMagic));

        byte[] truncated = Arrays.copyOf(good, good.length - 1);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(truncated));

        byte[] padded = Arrays.copyOf(good, good.length + 1);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(padded));

        byte[] unknownStage = good.clone();
        unknownStage[6] = 9;
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(unknownStage));

        byte[] slotCountLie = good.clone();
        slotCountLie[77] = (byte)(good[77] + 1);
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(slotCountLie));

        assertThrows(IllegalArgumentException.class,
                () -> AntiExfilAexb.decode(Arrays.copyOf(good, 40)));
        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.decode(null));
    }

    /**
     * A slot missing a field its stage requires must fail to encode rather than
     * be padded with zeroes into something that decodes as well-formed.
     */
    @Test
    public void incompleteSlotWillNotEncode() throws IOException {
        AntiExfilAexb.Message m4 =
                AntiExfilAexb.decode(hex(field(fixture(), "message_4_hex")));
        AntiExfilAexb.Slot first = m4.slots.get(0);
        AntiExfilAexb.Slot noSignature = new AntiExfilAexb.Slot(
                first.inputIndex, first.sighashType, first.signerPubkey, first.messageHash,
                first.hostCommitment, first.opening, null, null);

        assertThrows(IllegalArgumentException.class, () -> AntiExfilAexb.encode(
                new AntiExfilAexb.Message(m4.version, m4.network, AntiExfilAexb.STAGE_SIGNER_SIGNATURES,
                        m4.flags, m4.sessionId, m4.psbtDigest, List.of(noSignature))));
    }
}
