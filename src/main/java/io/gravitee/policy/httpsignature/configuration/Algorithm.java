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

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public enum Algorithm {
    HMAC_SHA1(org.tomitribe.auth.signatures.Algorithm.HMAC_SHA1),
    HMAC_SHA256(org.tomitribe.auth.signatures.Algorithm.HMAC_SHA256),
    HMAC_SHA384(org.tomitribe.auth.signatures.Algorithm.HMAC_SHA384),
    HMAC_SHA512(org.tomitribe.auth.signatures.Algorithm.HMAC_SHA512);

    private org.tomitribe.auth.signatures.Algorithm alg;

    Algorithm(org.tomitribe.auth.signatures.Algorithm alg) {
        this.alg = alg;
    }

    public org.tomitribe.auth.signatures.Algorithm getAlg() {
        return alg;
    }
}
