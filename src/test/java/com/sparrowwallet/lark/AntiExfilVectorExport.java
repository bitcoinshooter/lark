package com.sparrowwallet.lark;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Emits the crypto-layer anti-exfil vectors as JSON, for exchange with other
 * implementations of the same sign-to-contract construction.
 *
 * These are deliberately crypto-layer only: a tuple of (DER signature, signer
 * opening R0, host entropy rho, expected verdict) that any verifier can run
 * without parsing a PSBT, a proprietary field, or any transport envelope. That
 * is the layer at which two independent implementations can be compared
 * directly, so it is the layer at which agreement is meaningful.
 *
 * Note what is NOT here. There is no public key and no sighash, because the
 * vectors were generated from libwally's anti-exfil primitives rather than from
 * a signed transaction, so the message and key behind each signature are not
 * recoverable. A verifier that also performs full ECDSA validation therefore
 * cannot run these end to end; it must expose the s2c check separately, or
 * these must be regenerated from a signing key. Flagged here rather than
 * papered over, because it determines whether both corpora can run on both
 * verifiers.
 *
 * Run: java com.sparrowwallet.lark.AntiExfilVectorExport [output-path]
 */
public final class AntiExfilVectorExport {

    private static final String SCHEMA = "ae-ecdsa-crypto-v1";
    private static final String DEFAULT_OUT = "vectors/lark-ae-ecdsa-crypto-v1.json";

    private AntiExfilVectorExport() {}

    public static void main(String[] args) throws IOException {
        Path out = Paths.get(args.length > 0 ? args[0] : DEFAULT_OUT);
        if(out.getParent() != null) {
            Files.createDirectories(out.getParent());
        }

        Files.writeString(out, toJson(), StandardCharsets.UTF_8);
        System.out.println("Wrote " + AntiExfilVerifierTest.VECTORS.length + " vectors to " + out.toAbsolutePath());
    }

    static String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"schema\": \"").append(SCHEMA).append("\",\n");
        sb.append("  \"source\": \"lark AntiExfilVerifierTest, generated from libwally wally_ae_sig_from_bytes\",\n");
        sb.append("  \"curve\": \"secp256k1\",\n");
        sb.append("  \"construction\": {\n");
        sb.append("    \"host_commitment\": \"tagged_hash(\\\"s2c/ecdsa/data\\\", host_entropy)\",\n");
        sb.append("    \"tweak\": \"tagged_hash(\\\"s2c/ecdsa/point\\\", signer_commitment || host_entropy)\",\n");
        sb.append("    \"accept_if\": \"sig.r == (signer_commitment + tweak*G).x mod n\",\n");
        sb.append("    \"tweak_out_of_range\": \"rejected, not reduced mod n\"\n");
        sb.append("  },\n");
        sb.append("  \"encoding_rules\": {\n");
        sb.append("    \"signature\": \"DER, strictly canonical, optional single trailing sighash byte\",\n");
        sb.append("    \"low_s_required\": true,\n");
        sb.append("    \"scalars_in_range\": \"0 < r,s < n\"\n");
        sb.append("  },\n");
        sb.append("  \"notes\": [\n");
        sb.append("    \"No pubkey or message_hash: these exercise the s2c relation only, ")
          .append("so expected_ecdsa and expected_combined are null.\",\n");
        sb.append("    \"expected_s2c=false cases are protocol failures, not malformed input; ")
          .append("encoding-level rejection is covered by separate tests.\"\n");
        sb.append("  ],\n");
        sb.append("  \"tweak_boundary\": [\n");
        sb.append("    { \"id\": \"tweak-in-range\", \"tweak32\": \"").append("00".repeat(31)).append("01\", \"acceptable\": true },\n");
        sb.append("    { \"id\": \"tweak-zero\", \"tweak32\": \"").append("00".repeat(32)).append("\", \"acceptable\": false },\n");
        sb.append("    { \"id\": \"tweak-at-order\", \"tweak32\": \"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\", \"acceptable\": false },\n");
        sb.append("    { \"id\": \"tweak-max\", \"tweak32\": \"").append("ff".repeat(32)).append("\", \"acceptable\": false }\n");
        sb.append("  ],\n");
        sb.append("  \"vectors\": [\n");

        String[][] vectors = AntiExfilVerifierTest.VECTORS;
        for(int i = 0; i < vectors.length; i++) {
            String[] v = vectors[i];
            boolean expected = Boolean.parseBoolean(v[3]);
            sb.append("    {\n");
            sb.append("      \"id\": \"lark-").append(String.format("%02d", i)).append("\",\n");
            sb.append("      \"class\": \"").append(classify(i, expected)).append("\",\n");
            sb.append("      \"der_sig\": \"").append(v[0]).append("\",\n");
            sb.append("      \"signer_commitment\": \"").append(v[1]).append("\",\n");
            sb.append("      \"host_entropy\": \"").append(v[2]).append("\",\n");
            sb.append("      \"host_commitment\": \"").append(hostCommitmentHex(v[2])).append("\",\n");
            sb.append("      \"expected_s2c\": ").append(expected).append(",\n");
            sb.append("      \"expected_ecdsa\": null,\n");
            sb.append("      \"expected_combined\": null,\n");
            sb.append("      \"reason\": \"").append(reason(i, expected)).append("\"\n");
            sb.append("    }").append(i < vectors.length - 1 ? "," : "").append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /**
     * The host commitment is derivable from the entropy, but is emitted anyway.
     * A verifier that recomputes it and disagrees has a tagged-hash problem, and
     * finding that here is cheaper than finding it through a failing r check
     * with no indication of which step diverged.
     */
    private static String hostCommitmentHex(String entropyHex) {
        return bytesToHex(AntiExfilVerifier.hostCommitment(hexToBytes(entropyHex)));
    }

    private static String classify(int index, boolean expected) {
        if(index >= 16) {
            return "mismatched_pairing";
        }
        return expected ? "honest_signer" : "entropy_ignored";
    }

    private static String reason(int index, boolean expected) {
        if(index >= 16) {
            return "signature is valid for a different (commitment, entropy) pairing";
        }
        return expected
                ? "signature incorporates the host entropy as required"
                : "signature produced without the host entropy, i.e. signer ignored the protocol";
    }

    private static byte[] hexToBytes(String s) {
        byte[] b = new byte[s.length() / 2];
        for(int i = 0; i < b.length; i++) {
            b[i] = (byte)Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for(byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
