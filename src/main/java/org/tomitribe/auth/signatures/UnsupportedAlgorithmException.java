package org.tomitribe.auth.signatures;

public class UnsupportedAlgorithmException extends AuthenticationException {

    public UnsupportedAlgorithmException(final String message) {
        super(message);
    }

    public UnsupportedAlgorithmException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
