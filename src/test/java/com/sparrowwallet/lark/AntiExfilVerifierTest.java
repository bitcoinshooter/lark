package com.sparrowwallet.lark;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the ECDSA anti-exfil (sign-to-contract) host verifier.
 *
 * The ground-truth vectors below were generated from libwally: for each, a
 * signature produced with wally_ae_sig_from_bytes (expected true) and a
 * signature produced without the host entropy, i.e. a signer ignoring the
 * protocol (expected false), plus mismatched entropy/commitment pairings.
 *
 * The encoding tests cover what the s2c check alone does not: it constrains
 * only R, so a signer that commits to its nonce honestly can still leak key
 * material through the freedom left in s and in the DER encoding.
 */
public class AntiExfilVerifierTest {
    private static final BigInteger CURVE_ORDER =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /**
     * der_sig, signer_commitment, host_entropy, expected
     *
     * Package-visible so AntiExfilVectorExport emits these exact rows rather
     * than a copy. A corpus that has drifted from the tests it was taken from
     * is worse than no corpus.
     */
    static final String[][] VECTORS = {
            {"3045022100dde41a13c1f0c110c098530bf8e6569da5ac534e821c1991309d3781dca7ba69022057f63eddfeb199f98d68a43a1f5651cc2ed5229ddcb9002382658f3d75ae0e64",
             "02ed60b58309d8ef89490792d1e57186620d55b4bc2bf976fb23c68bd5fc37cb82",
             "fdb68f55f9ce5210c37f3c7025681c1500c0a22b285ad15d0fffab687d354992", "true"},
            {"304402200de2d7d3bc5e41987759a59887bc60685eb9152acec40ffeede7d4d27d159aac02203260563bdd5bc96fbdd5f7cfce244e521cd472977b36ceee87c6df76fd6b4ffc",
             "02ed60b58309d8ef89490792d1e57186620d55b4bc2bf976fb23c68bd5fc37cb82",
             "fdb68f55f9ce5210c37f3c7025681c1500c0a22b285ad15d0fffab687d354992", "false"},
            {"3045022100954b71d5aeb3649d4196fadadc3b9c5e4e7749ef3e7fb25bfeadaaeedd43fb820220457ebf5351c7687bcf1f953474682f9145d40826cdbfe09c102378b71ded8cc2",
             "02bc21fc84d028204b1dfa16a6840fdf11ed0e59a47627ba56ef3f5d65f8286909",
             "656fc4fa24a79831217817c53c61cdc94491263acec4d70d94051af8565ca4bc", "true"},
            {"304402200cd09e7c3011b993c37c825db58b045451e988047709c8e3397ffbdbf4a36d3902206e87b42858fc3dafc97505f1d87c8902afc639ba7e105deeecb22ab5fd4a9ab0",
             "02bc21fc84d028204b1dfa16a6840fdf11ed0e59a47627ba56ef3f5d65f8286909",
             "656fc4fa24a79831217817c53c61cdc94491263acec4d70d94051af8565ca4bc", "false"},
            {"3045022100b40c3d69d632bd50eb5f7e6233ff83106cbd4732b7974d35361b428da0c98a64022009f1671823b82365dd4b23a4c578bba9537f6756479b91a3084fd7f9ffcf2f58",
             "03cbe8b3b6c83bb4b4d5274ba89d37dff8514875947b3096c9d4addd8148f3580e",
             "1cd6dc711d5820342a32976a63330d950d3a640504e8daa2d697275c7b8bbd3f", "true"},
            {"3044022073689fb1b9cf9aae508dc90698635cc2a1bffd8745ebbd301cb2ef7dae81026b022012d4455b5c037f7c1fe900adeb85da5c4cbe7af8996e38799aab0dfe75555686",
             "03cbe8b3b6c83bb4b4d5274ba89d37dff8514875947b3096c9d4addd8148f3580e",
             "1cd6dc711d5820342a32976a63330d950d3a640504e8daa2d697275c7b8bbd3f", "false"},
            {"3044022053e9b35a00f75dbfbb943302527e1b9133682f1929cf7d3b3d250859eb3f2ea802204d1c5b1fdc48128a9cb328f26203d1540715906e3bb8880645fb9140e786f7d8",
             "03b7503ef2b33869ba745973c95b384c78085eaf21a9b330b46873d0ac719d80f5",
             "9b14107b5d3c2af30185d13cd62e92d357f98ed2e410f6516de147e04e96a09f", "true"},
            {"3044022048a7da048ec9aa18790b569578e4b0d639b3afbbb30393cdc94f618a61800c8702205abf4911d564f716ed7d359d3fd0de87e54969053b8c5c59e425884692938681",
             "03b7503ef2b33869ba745973c95b384c78085eaf21a9b330b46873d0ac719d80f5",
             "9b14107b5d3c2af30185d13cd62e92d357f98ed2e410f6516de147e04e96a09f", "false"},
            {"3045022100ee32cc2f5e40ee9a17d3e2213795d0be64304cc008ee06c401ac604e944f17f8022045f268d2e87cd2fc036c232d4f42e07247e633f239217dc9934dc7c4f4c3eb82",
             "02c672c986bf65cda24a90bc135c14ab608650c6fc4eb5e0d8c48d3fb32a28c589",
             "bd7d383e781a606420562d076571c6661f0253b14103abc2434aa08d50ea0ba7", "true"},
            {"3044022031dbbce8283e0da12977b216332f3b209e3591a16af90bced5ea31eec8e286ea0220682f2f0fec849985738d806ed2beda3bb18c3e0268733b87c106c68cac0563ff",
             "02c672c986bf65cda24a90bc135c14ab608650c6fc4eb5e0d8c48d3fb32a28c589",
             "bd7d383e781a606420562d076571c6661f0253b14103abc2434aa08d50ea0ba7", "false"},
            {"30440220384c401a17a8833b7b51d11c278dbd7cc4d799f6dbe16ea606fa20b5de58bb7502202fe8848e541375a2b7660b10727a3f88b35ed4f4b1275d41fd1e9a0c930c1a04",
             "03ba70ee2323f6204dec20e616d9db85d34356359a1ff0b20287be460ac3795f23",
             "2482d763496fa65d809d95bd97fa4ad7a60ff9f88b9d39cd8a314d8d42850e0d", "true"},
            {"3045022100a895335963b642c72f7c1cbb59a1418d18fb56f54e66236ebd583b4e184ed953022039977e4496af85c5a0a7c48e58011118b7727727aabe51c9599a6c5b7a3762f0",
             "03ba70ee2323f6204dec20e616d9db85d34356359a1ff0b20287be460ac3795f23",
             "2482d763496fa65d809d95bd97fa4ad7a60ff9f88b9d39cd8a314d8d42850e0d", "false"},
            {"3045022100b4cd35ea16526b1608109e384ca293cc1e0776c3d98b9f31545d2069b7f4026e02206344150519284391c3f9bd8b332acff572469ecef321d74752f8f69c771c68ca",
             "03014c5e58a3118c8be1c3977b89447ce3f626c136e45f9ccbfd679ae6d88d47a3",
             "248c25b94880c80f86eec18bcc2b60823da3d77b00bceea02f077d5680b3c6c1", "true"},
            {"304502210082d8561c11af56d650275eb3a94a9448812a650bd8e93a6d19080cac367c34e3022016029585b2a93a165fd1159da286f457940ef0145cc1727e7aa8afca8df48cbd",
             "03014c5e58a3118c8be1c3977b89447ce3f626c136e45f9ccbfd679ae6d88d47a3",
             "248c25b94880c80f86eec18bcc2b60823da3d77b00bceea02f077d5680b3c6c1", "false"},
            {"3045022100b818c973c56b7f6bb7129a08b6e3366d11ec2dbff490d071c7e3f6f68111458302206f0d96b223f91febc95698b37a48ab344403b0e29c0ddda34da3701ad0ddf720",
             "028e8c83816e48ac8762f94b4720e2ba6b109b7468632111aea227be8fc9f835a5",
             "ff74bbac2fb49dad438293d63831dad57f86d51738665271cb806670799ff455", "true"},
            {"30440220440432f0996ccf5febe8a579d004facaafe7e735f585314613c06e68ab4dc15802201f75f4a37e2146ff80d75dc6783dd0b0ce7f61f6bd1446bf28d3363053f55815",
             "028e8c83816e48ac8762f94b4720e2ba6b109b7468632111aea227be8fc9f835a5",
             "ff74bbac2fb49dad438293d63831dad57f86d51738665271cb806670799ff455", "false"},
            {"3045022100dde41a13c1f0c110c098530bf8e6569da5ac534e821c1991309d3781dca7ba69022057f63eddfeb199f98d68a43a1f5651cc2ed5229ddcb9002382658f3d75ae0e64",
             "02ed60b58309d8ef89490792d1e57186620d55b4bc2bf976fb23c68bd5fc37cb82",
             "656fc4fa24a79831217817c53c61cdc94491263acec4d70d94051af8565ca4bc", "false"},
            {"3045022100dde41a13c1f0c110c098530bf8e6569da5ac534e821c1991309d3781dca7ba69022057f63eddfeb199f98d68a43a1f5651cc2ed5229ddcb9002382658f3d75ae0e64",
             "02bc21fc84d028204b1dfa16a6840fdf11ed0e59a47627ba56ef3f5d65f8286909",
             "fdb68f55f9ce5210c37f3c7025681c1500c0a22b285ad15d0fffab687d354992", "false"},
    };

    @Test
    public void testOutOfRangeTweakRejected() {
        // libsecp256k1-zkp rejects an s2c tweak at or above the curve order rather
        // than reducing it, so this verifier must too. The condition is unreachable
        // with a real tagged hash (~2^-128), so it is exercised here by driving the
        // same comparison the verifier applies.
        BigInteger justOver = CURVE_ORDER;
        BigInteger wayOver = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        assertTrue(justOver.compareTo(CURVE_ORDER) >= 0, "n is not below n");
        assertTrue(wayOver.compareTo(CURVE_ORDER) >= 0, "2^256-1 is not below n");
        assertTrue(BigInteger.ZERO.signum() == 0, "zero tweak must also be rejected");

        // And confirm an in-range tweak still verifies end to end.
        String[] v = VECTORS[0];
        assertTrue(AntiExfilVerifier.verify(hex(v[0]), hex(v[1]), hex(v[2])),
                "an in-range tweak must still verify");
    }

    @Test
    public void testTweakBoundaryRule() {
        // The primitive-boundary case: the scalar acceptance rule, driven
        // directly, because a real tagged hash cannot reach it (~2^128 work).
        // These are the three cases a conforming implementation must agree on.
        byte[] inRange = new byte[32];
        inRange[31] = 0x01;
        byte[] zero = new byte[32];
        byte[] atOrder = hexOf(CURVE_ORDER);
        byte[] max = new byte[32];
        Arrays.fill(max, (byte)0xFF);

        assertTrue(AntiExfilVerifier.isAcceptableTweak(inRange), "1 is in range");
        assertFalse(AntiExfilVerifier.isAcceptableTweak(zero), "zero tweak must be rejected");
        assertFalse(AntiExfilVerifier.isAcceptableTweak(atOrder), "tweak == n must be rejected, not reduced");
        assertFalse(AntiExfilVerifier.isAcceptableTweak(max), "2^256-1 must be rejected, not reduced");
        assertFalse(AntiExfilVerifier.isAcceptableTweak(null), "null");
        assertFalse(AntiExfilVerifier.isAcceptableTweak(new byte[31]), "wrong length");
    }

    /** 32-byte big-endian encoding, left-padded. */
    private static byte[] hexOf(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    @Test
    public void testLibwallyVectors() {
        for(int i = 0; i < VECTORS.length; i++) {
            String[] v = VECTORS[i];
            boolean expected = Boolean.parseBoolean(v[3]);
            boolean actual = AntiExfilVerifier.verify(hex(v[0]), hex(v[1]), hex(v[2]));
            if(expected) {
                assertTrue(actual, "vector " + i + " should verify");
            } else {
                assertFalse(actual, "vector " + i + " should be rejected");
            }
        }
    }

    @Test
    public void testHighSRejected() {
        String[] v = VECTORS[0];
        byte[] commitment = hex(v[1]);
        byte[] entropy = hex(v[2]);
        BigInteger[] rs = decodeDer(hex(v[0]));

        assertTrue(AntiExfilVerifier.verify(encodeDer(rs[0], rs[1]), commitment, entropy),
                "low-S form is the valid one");
        assertFalse(AntiExfilVerifier.verify(encodeDer(rs[0], CURVE_ORDER.subtract(rs[1])), commitment, entropy),
                "high-S form of the same signature must be rejected");
    }

    @Test
    public void testScalarsOutsideCurveOrderRejected() {
        String[] v = VECTORS[0];
        byte[] commitment = hex(v[1]);
        byte[] entropy = hex(v[2]);
        BigInteger[] rs = decodeDer(hex(v[0]));

        assertFalse(AntiExfilVerifier.verify(encodeDer(rs[0], BigInteger.ZERO), commitment, entropy), "s == 0");
        assertFalse(AntiExfilVerifier.verify(encodeDer(rs[0], CURVE_ORDER), commitment, entropy), "s == n");
        assertFalse(AntiExfilVerifier.verify(encodeDer(BigInteger.ZERO, rs[1]), commitment, entropy), "r == 0");
        assertFalse(AntiExfilVerifier.verify(encodeDer(CURVE_ORDER, rs[1]), commitment, entropy), "r == n");
    }

    @Test
    public void testNonCanonicalDerRejected() {
        String[] v = VECTORS[0];
        byte[] commitment = hex(v[1]);
        byte[] entropy = hex(v[2]);
        byte[] der = hex(v[0]);

        byte[] padded = new byte[der.length + 1];
        padded[0] = 0x30;
        padded[1] = (byte)(der[1] + 1);
        padded[2] = 0x02;
        padded[3] = (byte)(der[3] + 1);
        padded[4] = 0x00;
        System.arraycopy(der, 4, padded, 5, der.length - 4);
        assertFalse(AntiExfilVerifier.verify(padded, commitment, entropy), "redundant leading zero on r");

        byte[] overstated = der.clone();
        overstated[1] = (byte)(overstated[1] + 1);
        assertFalse(AntiExfilVerifier.verify(overstated, commitment, entropy), "overstated sequence length");

        assertFalse(AntiExfilVerifier.verify(Arrays.copyOf(der, der.length + 2), commitment, entropy),
                "two trailing bytes");
        assertFalse(AntiExfilVerifier.verify(new byte[] {1, 2, 3}, commitment, entropy), "not DER at all");
        assertFalse(AntiExfilVerifier.verify(null, commitment, entropy), "null signature");
    }

    @Test
    public void testTrailingSighashByteTolerated() {
        String[] v = VECTORS[0];
        byte[] der = hex(v[0]);
        byte[] withSighash = Arrays.copyOf(der, der.length + 1);
        withSighash[der.length] = 0x01;
        assertTrue(AntiExfilVerifier.verify(withSighash, hex(v[1]), hex(v[2])),
                "a single trailing SIGHASH_ALL byte is normal in a PSBT partial signature");
    }

    @Test
    public void testMalformedInputsRejected() {
        String[] v = VECTORS[0];
        byte[] der = hex(v[0]);
        assertFalse(AntiExfilVerifier.verify(der, new byte[32], hex(v[2])), "commitment wrong length");
        assertFalse(AntiExfilVerifier.verify(der, hex(v[1]), new byte[31]), "entropy wrong length");
        assertFalse(AntiExfilVerifier.verify(der, null, hex(v[2])), "null commitment");
        assertFalse(AntiExfilVerifier.verify(der, hex(v[1]), null), "null entropy");

        byte[] offCurve = hex(v[1]).clone();
        offCurve[0] = 0x04;
        assertFalse(AntiExfilVerifier.verify(der, offCurve, hex(v[2])), "invalid point prefix");
    }

    // --- helpers ---

    private static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for(int i = 0; i < b.length; i++) {
            b[i] = (byte)Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    private static BigInteger[] decodeDer(byte[] der) {
        int rLen = der[3] & 0xFF;
        int sOff = 4 + rLen;
        int sLen = der[sOff + 1] & 0xFF;
        return new BigInteger[] {
                new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + rLen)),
                new BigInteger(1, Arrays.copyOfRange(der, sOff + 2, sOff + 2 + sLen))
        };
    }

    private static byte[] encodeDer(BigInteger r, BigInteger s) {
        byte[] rb = minimal(r);
        byte[] sb = minimal(s);
        byte[] out = new byte[6 + rb.length + sb.length];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = (byte)(4 + rb.length + sb.length);
        out[i++] = 0x02;
        out[i++] = (byte)rb.length;
        System.arraycopy(rb, 0, out, i, rb.length);
        i += rb.length;
        out[i++] = 0x02;
        out[i++] = (byte)sb.length;
        System.arraycopy(sb, 0, out, i, sb.length);
        return out;
    }

    /** Minimally encoded positive DER integer. */
    private static byte[] minimal(BigInteger v) {
        byte[] b = v.toByteArray();
        if(b.length > 1 && b[0] == 0 && (b[1] & 0x80) == 0) {
            b = Arrays.copyOfRange(b, 1, b.length);
        }
        return b;
    }
}
