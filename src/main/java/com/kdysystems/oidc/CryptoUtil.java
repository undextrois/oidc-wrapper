package com.kdysystems.oidc;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM encrypt/decrypt. Used for:
 *  - encrypting token/claims columns before they hit the SQLite file
 *  - encrypting the short-lived pending-auth cookie (state/nonce/verifier)
 *
 * GCM gives us confidentiality + integrity in one primitive, so no separate
 * HMAC step is needed on top of this.
 */
final class CryptoUtil {

    private static final String ALGO = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;   // bytes, GCM standard
    private static final int TAG_LENGTH = 128; // bits

    private final SecretKeySpec key;
    private final SecureRandom random = new SecureRandom();

    CryptoUtil(byte[] key32Bytes) {
        this.key = new SecretKeySpec(key32Bytes, "AES");
    }

    /** Returns base64(iv || ciphertext+tag) */
    String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /** Throws if the tag doesn't verify — treat any exception here as "reject, don't trust the input" */
    String decrypt(String base64Combined) {
        try {
            byte[] combined = Base64.getDecoder().decode(base64Combined);
            byte[] iv = new byte[IV_LENGTH];
            byte[] ciphertext = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(ALGO);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new SecurityException("Decryption/verification failed — tampered or corrupt value", e);
        }
    }
}
