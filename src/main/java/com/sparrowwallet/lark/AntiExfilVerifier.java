package com.sparrowwallet.lark;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Host-side verifier for the ECDSA anti-exfil (sign-to-contract) protocol as
 * implemented by libsecp256k1-zkp / libwally and Blockstream Jade.
 *
 * Construction (empirically pinned against libwally test vectors):
 *   t = tagged_hash("s2c/ecdsa/point", R0_compressed(33) || host_entropy(32)) mod n
 *   R = R0 + t*G
 *   valid iff sig.r == R.x mod n
 *
 * Pure Java (BigInteger EC math), no native deps. Validated against
 * ae_vectors.json generated from libwally.
 */
public final class AntiExfilVerifier {

    private static final BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger GX = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger GY = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final String S2C_POINT_TAG = "s2c/ecdsa/point";
    private static final String S2C_DATA_TAG = "s2c/ecdsa/data";
    private static final SecureRandom RANDOM = new SecureRandom();

    private AntiExfilVerifier() {}

    /** Generate fresh 32-byte host entropy. */
    public static byte[] generateHostEntropy() {
        byte[] entropy = new byte[32];
        RANDOM.nextBytes(entropy);
        return entropy;
    }

    /** AE_HOST_COMMITMENT = tagged_hash("s2c/ecdsa/data", host_entropy). */
    public static byte[] hostCommitment(byte[] hostEntropy) {
        require(hostEntropy != null && hostEntropy.length == 32, "host entropy must be 32 bytes");
        return taggedHash(S2C_DATA_TAG, hostEntropy);
    }

    /**
     * Verify a DER-encoded ECDSA signature incorporated the host entropy,
     * given the signer commitment R0 returned in round 1.
     * Callers MUST treat false as a signing-session hard failure.
     */
    public static boolean verify(byte[] derSignature, byte[] signerCommitment, byte[] hostEntropy) {
        try {
            require(signerCommitment != null && signerCommitment.length == 33, "signer commitment must be 33 bytes");
            require(hostEntropy != null && hostEntropy.length == 32, "host entropy must be 32 bytes");
            BigInteger r = derSigR(derSignature);
            BigInteger[] r0 = liftPoint(signerCommitment);

            byte[] msg = new byte[65];
            System.arraycopy(signerCommitment, 0, msg, 0, 33);
            System.arraycopy(hostEntropy, 0, msg, 33, 32);
            BigInteger t = new BigInteger(1, taggedHash(S2C_POINT_TAG, msg)).mod(N);

            BigInteger[] rPoint = add(r0, mul(t, new BigInteger[]{GX, GY}));
            return rPoint != null && rPoint[0].mod(N).equals(r);
        } catch (Exception e) {
            return false; // malformed inputs are verification failures
        }
    }

    // --- internals ---

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** BIP-340 style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
    private static byte[] taggedHash(String tag, byte[] msg) {
        byte[] tagHash = sha256(tag.getBytes(StandardCharsets.UTF_8));
        byte[] buf = new byte[64 + msg.length];
        System.arraycopy(tagHash, 0, buf, 0, 32);
        System.arraycopy(tagHash, 0, buf, 32, 32);
        System.arraycopy(msg, 0, buf, 64, msg.length);
        return sha256(buf);
    }

    /** Extract r from a DER ECDSA signature (trailing sighash byte tolerated). */
    private static BigInteger derSigR(byte[] der) {
        require(der != null && der.length > 8 && der[0] == 0x30, "not a DER signature");
        int rLen = der[3] & 0xFF;
        require(4 + rLen <= der.length, "truncated DER");
        return new BigInteger(1, Arrays.copyOfRange(der, 4, 4 + rLen));
    }

    /** Decompress a 33-byte SEC1 point. */
    private static BigInteger[] liftPoint(byte[] compressed) {
        int prefix = compressed[0] & 0xFF;
        require(prefix == 2 || prefix == 3, "invalid point prefix");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, 33));
        require(x.compareTo(P) < 0, "x out of range");
        BigInteger y2 = x.modPow(THREE, P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = y2.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        require(y.modPow(BigInteger.TWO, P).equals(y2), "x not on curve");
        if (y.testBit(0) != (prefix == 3)) {
            y = P.subtract(y);
        }
        return new BigInteger[]{x, y};
    }

    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        if (a == null) return b;
        if (b == null) return a;
        if (a[0].equals(b[0]) && a[1].add(b[1]).mod(P).signum() == 0) return null;
        BigInteger lambda;
        if (a[0].equals(b[0]) && a[1].equals(b[1])) {
            lambda = THREE.multiply(a[0]).multiply(a[0]).multiply(a[1].shiftLeft(1).modInverse(P)).mod(P);
        } else {
            lambda = b[1].subtract(a[1]).multiply(b[0].subtract(a[0]).modInverse(P)).mod(P);
        }
        BigInteger x3 = lambda.multiply(lambda).subtract(a[0]).subtract(b[0]).mod(P);
        BigInteger y3 = lambda.multiply(a[0].subtract(x3)).subtract(a[1]).mod(P);
        return new BigInteger[]{x3, y3};
    }

    private static BigInteger[] mul(BigInteger k, BigInteger[] point) {
        BigInteger[] result = null;
        BigInteger[] addend = point;
        while (k.signum() > 0) {
            if (k.testBit(0)) result = add(result, addend);
            addend = add(addend, addend);
            k = k.shiftRight(1);
        }
        return result;
    }

    private static void require(boolean cond, String msg) {
        if (!cond) throw new IllegalArgumentException(msg);
    }
}
