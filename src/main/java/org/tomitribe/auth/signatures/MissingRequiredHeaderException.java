package org.tomitribe.auth.signatures;

public class MissingRequiredHeaderException extends AuthenticationException {

    public MissingRequiredHeaderException(final String key) {
        super(key);
    }
}
