package com.muscy.encryption;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Implements AES (Advanced Encryption Standard) with Galois/Counter Mode (GCM), which is a mode of
 * operation for symmetric key cryptographic block ciphers that has been widely adopted because of
 * its efficiency and performance.
 * <p>
 * Every encryption produces a new 12 byte random IV (see http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 * because the security of GCM depends choosing a unique initialization vector for every encryption performed with the same key.
 * <p>
 * Key length must be >= 32 bytes
 * <p>
 * The iv, encrypted content and auth tag will be encoded to the following format:
 * <p>
 * out = byte[] {x y y y y y y y y y y y y z z z ...}
 * <p>
 * x = IV length as byte
 * y = IV bytes
 * z = content bytes (encrypted content, auth tag)
 */
public class EncryptionImpl implements Encryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int MIN_AES_KEY_LENGTH = 32; // for 256 byte key
    
    private final SecureRandom secureRandom;
    
    public EncryptionImpl() {
        this.secureRandom = new SecureRandom();
    }
    
    @Override
    public byte[] encrypt(final String key, final String dataToEncrypt) throws AuthenticatedEncryptionException {
        byte[] bytesToEncrypt = Encryption.convertStringToByteArray(dataToEncrypt);
        byte[] keyAsBytes = Encryption.convertHexStringToByteArray(key);
        return encrypt(keyAsBytes, bytesToEncrypt);
    }
    
    @Override
    public String encryptToString(final String key, final String dataToEncrypt) throws AuthenticatedEncryptionException {
        byte[] encrypted = encrypt(key, dataToEncrypt);
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    @Override
    public byte[] decrypt(final String key, final byte[] encryptedData) throws AuthenticatedEncryptionException {
        byte[] keyAsBytes = Encryption.convertHexStringToByteArray(key);
        byte[] decrypted = decrypt(keyAsBytes, encryptedData);
        return decrypted;
    }
    
    @Override
    public String decryptFromString(final String key, final String encryptedData) throws AuthenticatedEncryptionException {
        byte[] encryptedDataAsBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = decrypt(key, encryptedDataAsBytes);
        return Encryption.convertByteArrayToString(decrypted);
    }
    
    private byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData) throws AuthenticatedEncryptionException {
        if (rawEncryptionKey.length < MIN_AES_KEY_LENGTH) {
            throw new IllegalArgumentException("key length must be longer than " + MIN_AES_KEY_LENGTH + " bytes");
        }
        
        byte[] iv = null;
        byte[] encrypted = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);
            
            final Cipher cipherEnc = Cipher.getInstance(ALGORITHM);
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            encrypted = cipherEnc.doFinal(rawData);
            
            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        }
    }
    
    private byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData) throws AuthenticatedEncryptionException {
        byte[] iv = null;
        byte[] encrypted = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
            
            int ivLength = byteBuffer.get();
            iv = new byte[ivLength];
            byteBuffer.get(iv);
            encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);
            
            final Cipher cipherDec = Cipher.getInstance(ALGORITHM);
            cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            return cipherDec.doFinal(encrypted);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        }
    }
}

