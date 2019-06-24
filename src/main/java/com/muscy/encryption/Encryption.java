package com.muscy.encryption;

import java.io.UnsupportedEncodingException;


public interface Encryption {
    
    String CHARSET_UTF_8 = "UTF-8";
    
    byte[] encrypt(final String key, final String dataToEncrypt) throws AuthenticatedEncryptionException;
    byte[] decrypt(final String key, final byte[] encryptedData) throws AuthenticatedEncryptionException;
    
    String encryptToString(final String key, final String dataToEncrypt) throws AuthenticatedEncryptionException;
    String decryptFromString(final String key, final String encryptedData) throws AuthenticatedEncryptionException;
    
    static byte[] convertStringToByteArray(final String str) {
        try {
            return str.getBytes(CHARSET_UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticatedEncryptionException("Could not convert String to byte[] -invalid charset", e);
        }
    }
    
    static String convertByteArrayToString(byte[] bytes) {
        try {
            return new String(bytes, CHARSET_UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticatedEncryptionException("Could not convert byte[] to String -invalid charset", e);
        }
    }
    
    static byte[] convertHexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
