package org.tomitribe.auth.signatures;

public class UnparsableSignatureException extends AuthenticationException {

    public UnparsableSignatureException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
