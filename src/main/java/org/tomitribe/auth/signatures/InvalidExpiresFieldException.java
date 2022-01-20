package org.tomitribe.auth.signatures;

public class InvalidExpiresFieldException extends AuthenticationException {

    public InvalidExpiresFieldException(final String message) {
        super(message);
    }
}
