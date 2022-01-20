/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.httpsignature.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class HttpSignaturePolicyConfiguration implements PolicyConfiguration {

    private HttpSignatureScheme scheme;

    // List of supported HMAC digest algorithms.
    private List<Algorithm> algorithms;

    private String secret;

    // List of headers which the client should at least use for HTTP signature creation
    private List<String> enforceHeaders;

    // Clock Skew in seconds to prevent replay attacks.
    private long clockSkew = 30;

    private boolean decodeSignature;

    private boolean strictMode = true;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getClockSkew() {
        return clockSkew;
    }

    public void setClockSkew(long clockSkew) {
        this.clockSkew = clockSkew;
    }

    public HttpSignatureScheme getScheme() {
        return scheme;
    }

    public void setScheme(HttpSignatureScheme scheme) {
        this.scheme = scheme;
    }

    public List<Algorithm> getAlgorithms() {
        return algorithms;
    }

    public void setAlgorithms(List<Algorithm> algorithms) {
        this.algorithms = algorithms;
    }

    public List<String> getEnforceHeaders() {
        return enforceHeaders;
    }

    public void setEnforceHeaders(List<String> enforceHeaders) {
        this.enforceHeaders = enforceHeaders;
    }

    public boolean isDecodeSignature() {
        return decodeSignature;
    }

    public void setDecodeSignature(boolean decodeSignature) {
        this.decodeSignature = decodeSignature;
    }

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }
}
