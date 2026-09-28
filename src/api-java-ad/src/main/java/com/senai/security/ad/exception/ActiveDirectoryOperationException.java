package com.senai.security.ad.exception;

public class ActiveDirectoryOperationException extends RuntimeException {
    public ActiveDirectoryOperationException(String message) {
        super(message);
    }
    public ActiveDirectoryOperationException(String message, Throwable cause) {
        super(message, cause);
    }
}
