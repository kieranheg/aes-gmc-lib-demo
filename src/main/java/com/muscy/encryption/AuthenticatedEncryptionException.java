package com.muscy.encryption;

class AuthenticatedEncryptionException extends RuntimeException {

    AuthenticatedEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
