package com.muscy.encryption;

/**
 * Thrown during the process of {@link AuthenticatedEncryptionException}
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */

public class AuthenticatedEncryptionException extends RuntimeException {

    public AuthenticatedEncryptionException(String message) {
        super(message);
    }

    public AuthenticatedEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
