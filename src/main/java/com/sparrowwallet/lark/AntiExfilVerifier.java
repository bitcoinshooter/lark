package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.SignatureDecodeException;

import java.math.BigInteger;
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
 * The r check alone is not sufficient. Signatures are also required to be
 * strictly DER encoded, with both scalars inside the curve order and s in its
 * low form, since any encoding freedom left to the device is a residual channel
 * for leaking key material a bit at a time.
 *
 * Drongo supplies the tagged hash, the signature decoding and canonicality
 * rules, the curve order, and the scalar multiplication t*G. The remaining
 * point decompression and single addition are done here with BigInteger,
 * because drongo does not export the Bouncy Castle point types it uses
 * internally. This is public verification touching no secret key material, so
 * the non-constant-time arithmetic is not a side-channel concern; the secret
 * nonce lives only on the signing device.
 */
public final class AntiExfilVerifier {
    /** secp256k1 field prime. Needed for point decompression; drongo exposes the curve order but not this. */
    private static final BigInteger FIELD_PRIME =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final String S2C_POINT_TAG = "s2c/ecdsa/point";
    private static final String S2C_DATA_TAG = "s2c/ecdsa/data";
    /** Host entropy is 32 bytes. Package-visible: the session validates against it. */
    static final int ENTROPY_LEN = 32;
    private static final int COMMITMENT_LEN = 33;
    private static final SecureRandom RANDOM = new SecureRandom();

    private AntiExfilVerifier() {}

    /**
     * Whether a 32-byte s2c tweak is acceptable as a scalar.
     *
     * libsecp256k1-zkp REJECTS a tweak at or above the curve order rather than
     * reducing it: secp256k1_ec_pubkey_tweak_add_helper returns !overflow &amp;&amp; ...,
     * so secp256k1_ec_commit fails and ecdsa_s2c_verify returns 0. Reducing here
     * would make this verifier more permissive than the signer it is checking,
     * which is the wrong direction for a security check.
     *
     * Exposed separately because the rule cannot be reached through a real
     * tagged hash - producing an out-of-range one is roughly 2^128 work - so an
     * end-to-end vector can never exercise it. Driving the scalar directly is
     * the only way to test the boundary, and it lets other implementations
     * conform against the same three cases: in range, zero, at or above n.
     */
    public static boolean isAcceptableTweak(byte[] tweak32) {
        if(tweak32 == null || tweak32.length != ENTROPY_LEN) {
            return false;
        }

        BigInteger tweak = new BigInteger(1, tweak32);
        return tweak.signum() != 0 && tweak.compareTo(ECKey.CURVE_ORDER) < 0;
    }

    /** Generate fresh 32-byte host entropy. */
    public static byte[] generateHostEntropy() {
        byte[] entropy = new byte[ENTROPY_LEN];
        RANDOM.nextBytes(entropy);
        return entropy;
    }

    /** AE_HOST_COMMITMENT = tagged_hash("s2c/ecdsa/data", host_entropy). */
    public static byte[] hostCommitment(byte[] hostEntropy) {
        if(hostEntropy == null || hostEntropy.length != ENTROPY_LEN) {
            throw new IllegalArgumentException("Host entropy must be " + ENTROPY_LEN + " bytes");
        }

        return Utils.taggedHash(S2C_DATA_TAG, hostEntropy);
    }

    /**
     * Verify a DER-encoded ECDSA signature incorporated the host entropy, given
     * the signer commitment R0 returned in round 1. Callers MUST treat false as
     * a signing-session hard failure.
     *
     * Fails closed: any malformed input (bad DER, off-curve point, wrong
     * lengths) comes from an untrusted signing device, so a parse failure is
     * itself a verification failure. Never returns true on exception.
     */
    public static boolean verify(byte[] derSignature, byte[] signerCommitment, byte[] hostEntropy) {
        try {
            if(signerCommitment == null || signerCommitment.length != COMMITMENT_LEN
                    || hostEntropy == null || hostEntropy.length != ENTROPY_LEN) {
                return false;
            }

            // The s2c construction below constrains only R. Everything else the
            // device controls in the encoding is a residual covert channel, so
            // constrain that here: strictly canonical DER (no padded integers,
            // no negative scalars), and a low S value. Otherwise a device that
            // commits to its nonce honestly can still leak a bit of key material
            // per signature by choosing between the low and high S forms.
            ECDSASignature signature = decodeCanonical(derSignature);
            if(signature == null || !signature.isCanonical()
                    || signature.r.signum() <= 0 || signature.r.compareTo(ECKey.CURVE_ORDER) >= 0
                    || signature.s.signum() <= 0 || signature.s.compareTo(ECKey.CURVE_ORDER) >= 0) {
                return false;
            }

            byte[] message = new byte[COMMITMENT_LEN + ENTROPY_LEN];
            System.arraycopy(signerCommitment, 0, message, 0, COMMITMENT_LEN);
            System.arraycopy(hostEntropy, 0, message, COMMITMENT_LEN, ENTROPY_LEN);
            // Scalar acceptance rule is in isAcceptableTweak() so that the
            // boundary can be tested directly; a real tagged hash never reaches
            // it. The gap between 2^256 and n is ~2^128, so this is a
            // conformance matter, not a live case.
            byte[] tweakBytes = Utils.taggedHash(S2C_POINT_TAG, message);
            if(!isAcceptableTweak(tweakBytes)) {
                return false;
            }
            BigInteger tweak = new BigInteger(1, tweakBytes);

            BigInteger[] r0 = decompress(signerCommitment);
            BigInteger[] tweakPoint = decompress(ECKey.publicKeyFromPrivate(tweak, true));
            BigInteger[] point = add(r0, tweakPoint);
            if(point == null) {
                return false;
            }

            return point[0].mod(ECKey.CURVE_ORDER).equals(signature.r);
        } catch(Exception e) {
            return false;
        }
    }

    /**
     * Strictly decode a DER signature, with or without a trailing sighash byte.
     *
     * ECDSASignature.decodeFromDER() deliberately relaxes ASN.1 integer parsing,
     * because pre-BIP66 signatures with padded integers exist on chain and a
     * wallet must still verify them. That tolerance is the wrong default here:
     * the padding freedom is itself a covert channel. So the raw bytes are put
     * through isEncodingCanonical() first, which applies the BIP66-style rules.
     *
     * isEncodingCanonical() expects the trailing sighash byte present in a PSBT
     * partial signature, so a bare DER signature has SIGHASH_ALL appended before
     * the check. The appended byte is not otherwise used - which sighash type
     * was signed is checked elsewhere, against the transaction.
     *
     * @return the decoded signature, or null if the encoding is not canonical
     */
    private static ECDSASignature decodeCanonical(byte[] derSignature) throws SignatureDecodeException {
        if(derSignature == null || derSignature.length < 8) {
            return null;
        }

        byte[] withSigHash = derSignature;
        int sequenceLength = derSignature[1] & 0xFF;
        if(sequenceLength == derSignature.length - 2) {
            withSigHash = Arrays.copyOf(derSignature, derSignature.length + 1);
            withSigHash[derSignature.length] = 0x01; // SIGHASH_ALL
        }

        if(!ECDSASignature.isEncodingCanonical(withSigHash)) {
            return null;
        }

        return ECDSASignature.decodeFromDER(derSignature);
    }

    /** Decompress a 33-byte SEC1 point to affine {x, y}. */
    private static BigInteger[] decompress(byte[] compressed) {
        int prefix = compressed[0] & 0xFF;
        if(prefix != 2 && prefix != 3) {
            throw new IllegalArgumentException("Invalid point prefix");
        }

        BigInteger x = new BigInteger(1, Arrays.copyOfRange(compressed, 1, COMMITMENT_LEN));
        if(x.compareTo(FIELD_PRIME) >= 0) {
            throw new IllegalArgumentException("Point x coordinate out of range");
        }

        BigInteger ySquared = x.modPow(THREE, FIELD_PRIME).add(SEVEN).mod(FIELD_PRIME);
        BigInteger y = ySquared.modPow(FIELD_PRIME.add(BigInteger.ONE).shiftRight(2), FIELD_PRIME);
        if(!y.modPow(BigInteger.TWO, FIELD_PRIME).equals(ySquared)) {
            throw new IllegalArgumentException("Point not on curve");
        }

        if(y.testBit(0) != (prefix == 3)) {
            y = FIELD_PRIME.subtract(y);
        }

        return new BigInteger[] {x, y};
    }

    /** Affine point addition. Returns null for the point at infinity. */
    private static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        if(a[0].equals(b[0]) && a[1].add(b[1]).mod(FIELD_PRIME).signum() == 0) {
            return null;
        }

        BigInteger lambda;
        if(a[0].equals(b[0]) && a[1].equals(b[1])) {
            lambda = THREE.multiply(a[0]).multiply(a[0])
                    .multiply(a[1].shiftLeft(1).modInverse(FIELD_PRIME)).mod(FIELD_PRIME);
        } else {
            lambda = b[1].subtract(a[1])
                    .multiply(b[0].subtract(a[0]).modInverse(FIELD_PRIME)).mod(FIELD_PRIME);
        }

        BigInteger x = lambda.multiply(lambda).subtract(a[0]).subtract(b[0]).mod(FIELD_PRIME);
        BigInteger y = lambda.multiply(a[0].subtract(x)).subtract(a[1]).mod(FIELD_PRIME);
        return new BigInteger[] {x, y};
    }
}
