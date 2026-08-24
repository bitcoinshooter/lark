package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTInput;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the two-round anti-exfil orchestration.
 *
 * Fixtures are the four PSBTs from a real testnet4 signing against a Jade
 * (Blockstream/Jade#332), so the honest path here is the exchange that actually
 * happened on hardware rather than something synthesised to pass.
 */
public class AntiExfilSessionTest {
    /** Round 1 as sent to the device: host_commitment only, no signature. */
    private static final String ROUND1_OUT = "cHNidP8BAHECAAAAAXpiHHv0vbMTinDyORybtvCt+k2P6LEQiqAPeq7dj+gNAAAAAAD9////AtetBAAAAAAAFgAUWkZSP9IEoHCO33qslptpJid91mPECQAAAAAAABYAFIyERlj3zIAceTlZw7RePzB2wyH5FEgCAE8BBDWHzwP6XrUdgAAAADWpq3uDb1Elgd7d0ZSOwY/MDsVA8v6kO1Px7B8sca38A1a3JrPTU1LXWf9+IIY81GPpaK9OOISCUwGT14IhEFNiEOxmhqhUAACAAQAAgAAAAIAAAQEf4bcEAAAAAAAWABQ1WG1nXXBE35ifVrgOTFKc3lWlzQEDBAEAAAAiBgKRX9Y4ioP9NfQe+OxQBLNyy2Fmg9OsEU1IExpiVJyNGhjsZoaoVAAAgAEAAIAAAACAAQAAAAUAAAAm/AJhZQACkV/WOIqD/TX0HvjsUASzcsthZoPTrBFNSBMaYlScjRogxtZdV8oySW4MxrHKx6nE4+5PtwyT40FB6ZYTi0VWQxoAIgICNEbnW0vkGuV6YksezfrKNfpGX1j1O9veU+72uoYP82kY7GaGqFQAAIABAACAAAAAgAEAAAAGAAAAAAA=";

    /** The device's round 1 reply: signer_commitment added, still unsigned. */
    private static final String ROUND1_REPLY = "cHNidP8BAHECAAAAAXpiHHv0vbMTinDyORybtvCt+k2P6LEQiqAPeq7dj+gNAAAAAAD9////AtetBAAAAAAAFgAUWkZSP9IEoHCO33qslptpJid91mPECQAAAAAAABYAFIyERlj3zIAceTlZw7RePzB2wyH5FEgCAE8BBDWHzwP6XrUdgAAAADWpq3uDb1Elgd7d0ZSOwY/MDsVA8v6kO1Px7B8sca38A1a3JrPTU1LXWf9+IIY81GPpaK9OOISCUwGT14IhEFNiEOxmhqhUAACAAQAAgAAAAIAAAQEf4bcEAAAAAAAWABQ1WG1nXXBE35ifVrgOTFKc3lWlzQEDBAEAAAAiBgKRX9Y4ioP9NfQe+OxQBLNyy2Fmg9OsEU1IExpiVJyNGhjsZoaoVAAAgAEAAIAAAACAAQAAAAUAAAAm/AJhZQACkV/WOIqD/TX0HvjsUASzcsthZoPTrBFNSBMaYlScjRogxtZdV8oySW4MxrHKx6nE4+5PtwyT40FB6ZYTi0VWQxom/AJhZQECkV/WOIqD/TX0HvjsUASzcsthZoPTrBFNSBMaYlScjRohAu3SNG/Nsogshm8IFFKxa0Uo5ygaZmenoW/ZdsPHV5h0ACICAjRG51tL5BrlemJLHs36yjX6Rl9Y9Tvb3lPu9rqGD/NpGOxmhqhUAACAAQAAgAAAAIABAAAABgAAAAAA";

    /** The device's round 2 reply: signed. */
    private static final String ROUND2_REPLY = "cHNidP8BAHECAAAAAXpiHHv0vbMTinDyORybtvCt+k2P6LEQiqAPeq7dj+gNAAAAAAD9////AtetBAAAAAAAFgAUWkZSP9IEoHCO33qslptpJid91mPECQAAAAAAABYAFIyERlj3zIAceTlZw7RePzB2wyH5FEgCAE8BBDWHzwP6XrUdgAAAADWpq3uDb1Elgd7d0ZSOwY/MDsVA8v6kO1Px7B8sca38A1a3JrPTU1LXWf9+IIY81GPpaK9OOISCUwGT14IhEFNiEOxmhqhUAACAAQAAgAAAAIAAAQEf4bcEAAAAAAAWABQ1WG1nXXBE35ifVrgOTFKc3lWlzSICApFf1jiKg/019B747FAEs3LLYWaD06wRTUgTGmJUnI0aSDBFAiEAjtkpS9R7t1LMXBKwTDOaUhR9FazhdvbVeLu32ynBlHICIHd4iJVp/qsKIgbEXSYDF04BreU17L5y7zsLVV6xY7JXAQEDBAEAAAAiBgKRX9Y4ioP9NfQe+OxQBLNyy2Fmg9OsEU1IExpiVJyNGhjsZoaoVAAAgAEAAIAAAACAAQAAAAUAAAAm/AJhZQACkV/WOIqD/TX0HvjsUASzcsthZoPTrBFNSBMaYlScjRogxtZdV8oySW4MxrHKx6nE4+5PtwyT40FB6ZYTi0VWQxom/AJhZQECkV/WOIqD/TX0HvjsUASzcsthZoPTrBFNSBMaYlScjRohAu3SNG/Nsogshm8IFFKxa0Uo5ygaZmenoW/ZdsPHV5h0JvwCYWUCApFf1jiKg/019B747FAEs3LLYWaD06wRTUgTGmJUnI0aIEDQGjxnxvdiUZlZ6vAT+HG10CTK9wtozGVS0KE5OUk6ACICAjRG51tL5BrlemJLHs36yjX6Rl9Y9Tvb3lPu9rqGD/NpGOxmhqhUAACAAQAAgAAAAIABAAAABgAAAAAA";

    private static final String SIGNER_PUBKEY = "02915fd6388a83fd35f41ef8ec5004b372cb616683d3ac114d48131a62549c8d1a";

    private static Network originalNetwork;

    /**
     * The fixtures are testnet4 PSBTs and carry a tpub in the global xpub field,
     * which drongo rejects while the static network is mainnet. Network.set
     * permits reassignment inside a Gradle test worker, so set it for the class
     * and restore afterwards rather than leaking it into other tests.
     */
    @BeforeAll
    public static void useTestnet() {
        originalNetwork = Network.get();
        Network.set(Network.TESTNET);
    }

    @AfterAll
    public static void restoreNetwork() {
        Network.set(originalNetwork);
    }

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for(int i = 0; i < b.length; i++) {
            b[i] = (byte)Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    /**
     * A session over the same transaction the hardware run used. buildRound1 is
     * not called, so the session generates its own entropy - which means only
     * the structural assertions hold against the recorded reply, not the s2c
     * verification. Tests that need the real entropy say so.
     */
    private static AntiExfilSession session() throws Exception {
        return new AntiExfilSession(b64(ROUND1_OUT),
                Map.of(0, List.of(hex(SIGNER_PUBKEY))));
    }

    // --- transaction pinning ---

    @Test
    public void testRound1ReplyForDifferentTransactionRejected() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();

        // A PSBT for an entirely different transaction, correctly formed otherwise.
        PSBT other = new PSBT(b64(ROUND1_REPLY));
        other.getTransaction().setLocktime(other.getTransaction().getLocktime() + 1);

        SecurityException e = assertThrows(SecurityException.class,
                () -> session.acceptRound1Reply(other.serialize()));
        assertTrue(e.getMessage().contains("different transaction"), e.getMessage());
    }

    @Test
    public void testSignedReplyForDifferentTransactionRejected() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        // Deliberately unsigned. Mutating the locktime of the signed reply would
        // invalidate its signature against the transaction, and drongo rejects
        // that with a PSBTSignatureException before verifyAndExtract's own checks
        // run - which would test drongo rather than the txid pinning. An unsigned
        // PSBT for a different transaction reaches requireSameTransaction, which
        // is the first thing verifyAndExtract does.
        PSBT other = new PSBT(b64(ROUND1_OUT));
        other.getTransaction().setLocktime(other.getTransaction().getLocktime() + 1);

        SecurityException e = assertThrows(SecurityException.class,
                () -> session.verifyAndExtract(other.serialize()));
        assertTrue(e.getMessage().contains("different transaction"), e.getMessage());
    }

    // --- protocol ordering ---

    @Test
    public void testDeviceSigningInRoundOneRejected() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();

        // The round 2 reply is signed; presenting it as a round 1 reply must be
        // rejected - a device that signs before the entropy is revealed has not
        // committed to anything.
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> session.acceptRound1Reply(b64(ROUND2_REPLY)));
        assertTrue(e.getMessage().contains("signed during commitment round"), e.getMessage());
    }

    @Test
    public void testMissingSignerCommitmentRejected() throws Exception {
        AntiExfilSession session = session();
        byte[] round1 = session.buildRound1();

        // Echoing round 1 back unchanged: no signer commitment was added, which is
        // what an anti-exfil-unaware device would do.
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> session.acceptRound1Reply(round1));
        assertTrue(e.getMessage().contains("did not return anti-exfil commitment"), e.getMessage());
    }

    // --- retry / selective abort resistance ---

    @Test
    public void testEntropyIsStableAcrossRebuilds() throws Exception {
        AntiExfilSession session = session();
        byte[] first = session.buildRound1();
        byte[] second = session.buildRound1();

        // Same session, same entropy, so the host commitment must be identical.
        // Re-randomising would hand an aborting device a fresh nonce draw.
        assertEquals(commitmentHex(first), commitmentHex(second),
                "host commitment changed between rebuilds of the same session");
    }

    @Test
    public void testChangedSignerCommitmentOnRetryRejected() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        // Same transaction, same round, but the device now proposes a different R0.
        PSBT tampered = new PSBT(b64(ROUND1_REPLY));
        PSBTInput input = tampered.getPsbtInputs().get(0);
        String key = signerCommitmentKey();
        String original = input.getProprietary().get(key);
        assertNotNull(original, "fixture is missing the signer commitment");
        input.getProprietary().put(key, flipLastByte(original));

        SecurityException e = assertThrows(SecurityException.class,
                () -> session.acceptRound1Reply(tampered.serialize()));
        assertTrue(e.getMessage().contains("different anti-exfil commitment on retry"), e.getMessage());
    }

    @Test
    public void testRepeatedIdenticalReplyAccepted() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        // An honest retry - identical reply - must not be treated as an attack.
        session.acceptRound1Reply(b64(ROUND1_REPLY));
    }

    // --- round 2 contents ---

    @Test
    public void testRoundTwoCarriesAllThreeFields() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        PSBT round2 = new PSBT(session.buildRound2());
        long aeFields = round2.getPsbtInputs().get(0).getProprietary().keySet().stream()
                .filter(k -> k.toLowerCase(java.util.Locale.ROOT).startsWith("026165")).count();
        assertEquals(3, aeFields, "round 2 should carry host_commitment, signer_commitment and host_entropy");
    }

    @Test
    public void testRoundTwoIsUnsigned() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        PSBT round2 = new PSBT(session.buildRound2());
        assertTrue(round2.getPsbtInputs().get(0).getPartialSignatures().isEmpty(),
                "the host must not send signatures to the device");
    }

    // --- verification failure ---

    @Test
    public void testSignatureNotIncorporatingOurEntropyRejected() throws Exception {
        AntiExfilSession session = session();
        session.buildRound1();
        session.acceptRound1Reply(b64(ROUND1_REPLY));

        // The recorded signature was produced against the entropy from the real
        // run, not this session's, so verification must fail. This is the same
        // shape as a device that ignored the host entropy entirely.
        SecurityException e = assertThrows(SecurityException.class,
                () -> session.verifyAndExtract(b64(ROUND2_REPLY)));
        assertTrue(e.getMessage().contains("ANTI-EXFIL VERIFICATION FAILED"), e.getMessage());
    }

    // --- helpers ---

    private static String signerCommitmentKey() {
        // drongo keys proprietary entries by the data after the 0xFC byte:
        // 02 6165 <subtype> <pubkey33>. Subtype 0x01 is the signer commitment.
        return "026165" + "01" + SIGNER_PUBKEY;
    }

    private static String commitmentHex(byte[] psbtBytes) throws Exception {
        PSBT psbt = new PSBT(psbtBytes);
        return psbt.getPsbtInputs().get(0).getProprietary().get("026165" + "00" + SIGNER_PUBKEY);
    }

    private static String flipLastByte(String hex) {
        int last = Integer.parseInt(hex.substring(hex.length() - 2), 16) ^ 1;
        return hex.substring(0, hex.length() - 2) + String.format("%02x", last);
    }
}
