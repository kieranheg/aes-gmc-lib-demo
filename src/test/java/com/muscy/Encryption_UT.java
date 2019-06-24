package com.muscy;

import com.muscy.encryption.EncryptionImpl;
import com.muscy.encryption.Encryption;
import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

public class Encryption_UT {
    
    private static final String ENCRYPTION_KEY = "ab!de=a01defABcda;cdeFabcdefa99dab!de=a01:efABcdabcdeFab!defa99d";
    public static final String DATA_TO_ENCRYPT = "test data 01";
    
    private Encryption aes = new EncryptionImpl();
    
    @Test
    public void testEncryption() {
        byte[] encryptedData = aes.encrypt(ENCRYPTION_KEY, DATA_TO_ENCRYPT);
        byte[] decryptedData = aes.decrypt(ENCRYPTION_KEY, encryptedData);
        assertEquals(DATA_TO_ENCRYPT, Encryption.convertByteArrayToString(decryptedData));
    }
}
