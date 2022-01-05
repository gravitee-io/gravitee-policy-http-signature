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
package io.gravitee.policy.httpsignature;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.httpsignature.configuration.HttpSignaturePolicyConfiguration;
import io.gravitee.policy.httpsignature.configuration.HttpSignatureScheme;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class HttpSignaturePolicy {

    private static final String HTTP_SIGNATURE_INVALID_SIGNATURE = "HTTP_SIGNATURE_INVALID_SIGNATURE";

    static final String HTTP_HEADER_SIGNATURE = "Signature";

    /**
     * Policy configuration
     */
    private final HttpSignaturePolicyConfiguration configuration;

    public HttpSignaturePolicy(final HttpSignaturePolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext context, PolicyChain chain) {
        // Extract the signature according to the scheme
        final Signature signature = extractSignature(request);

        if (signature == null ||
                ! enforceAlgorithm(signature) ||
                ! enforceHeaders(signature) ||
                ! validateHeaders(signature, request) ||
                ! verifySignatureValidityDates(signature) ||
                ! verifySignature(signature, context, request)) {
            chain.failWith(PolicyResult.failure(HTTP_SIGNATURE_INVALID_SIGNATURE, 401, "Invalid HTTP Signature"));

            return ;
        }

        chain.doNext(request, response);
    }

    private boolean verifySignature(final Signature reqSignature, final ExecutionContext context, final Request request) {
        try {
            Long maxSignatureValidationDuration = null;
            if (reqSignature.getSignatureCreationTimeMilliseconds() != null && reqSignature.getSignatureExpirationTimeMilliseconds() != null) {
                maxSignatureValidationDuration = reqSignature.getSignatureExpirationTimeMilliseconds() - reqSignature.getSignatureCreationTimeMilliseconds();
            }

            Signature signature = new Signature(reqSignature.getKeyId(), reqSignature.getSigningAlgorithm(),
                    reqSignature.getAlgorithm(), reqSignature.getParameterSpec(), null,
                    reqSignature.getHeaders(), maxSignatureValidationDuration, reqSignature.getSignatureCreationTimeMilliseconds(),
                    reqSignature.getSignatureExpirationTimeMilliseconds());

            context.getTemplateEngine().getTemplateContext().setVariable("keyId", reqSignature.getKeyId());

            String secret = context.getTemplateEngine().getValue(configuration.getSecret(), String.class);
            final Key key = new SecretKeySpec(secret.getBytes(), reqSignature.getAlgorithm().getJvmName());
            final Signer signer = new Signer(key, signature);


            final Signature signed = signer.sign(request.method().name().toLowerCase(), request.path(),
                    request.headers().toSingleValueMap(), reqSignature.getSignatureCreationTimeMilliseconds(), reqSignature.getSignatureExpirationTimeMilliseconds());

            String sReqSignature = reqSignature.getSignature();
            if (configuration.isDecodeSignature()) {
                sReqSignature = URLDecoder.decode(sReqSignature, StandardCharsets.UTF_8.name());
            }

            // Check signature
            return signed.getSignature().equals(sReqSignature);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Verify the signature is valid with regards to the (created) and (expires) fields.
     *
     * When the '(created)' field is present in the HTTP signature, the '(created)' field
     * represents the date when the signature has been created.
     * When the '(expires)' field is present in the HTTP signature, the '(expires)' field
     * represents the date when the signature expires.
     */
    private boolean verifySignatureValidityDates(Signature signature) {
        if (configuration.getClockSkew() > 0) {
            if (signature.getSignatureCreationTimeMilliseconds() != null &&
                    signature.getSignatureCreationTimeMilliseconds() > System.currentTimeMillis() + (configuration.getClockSkew() * 1_000)) {
                return false;
            }

            if (signature.getSignatureExpirationTimeMilliseconds() != null && signature.getSignatureExpirationTimeMilliseconds() < System.currentTimeMillis()) {
                return false;
            }
        }

        return true;
    }

    private boolean enforceHeaders(final Signature signature) {
        List<String> sigHeaders = signature.getHeaders();
        if (configuration.getEnforceHeaders() != null && !configuration.getEnforceHeaders().isEmpty()) {
            // We don't have to check headers is the same is not matching
            if (configuration.getEnforceHeaders().size() > sigHeaders.size()) {
                return false;
            }

            return configuration.getEnforceHeaders().stream()
                    .map(String::toLowerCase)
                    .filter(header -> !header.startsWith("(") && !header.endsWith(")"))
                    .allMatch(sigHeaders::contains);
        }

        return true;
    }

    /**
     * https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.section.2.5
     * If a header specified in the `headers` value of the Signature Parameters (or the default item `(created)`
     * where the `headers` value is not supplied) is absent from the message, the implementation MUST produce an error.
     *
     * @param signature
     * @param request
     * @return
     */
    private boolean validateHeaders(final Signature signature, final Request request) {
        List<String> sigHeaders = signature.getHeaders();
        return sigHeaders.stream()
                .filter(header -> !header.startsWith("(") && !header.endsWith(")"))
                .allMatch(request.headers()::containsKey);
    }

    private boolean enforceAlgorithm(final Signature signature) {
        if (configuration.getAlgorithms() != null && !configuration.getAlgorithms().isEmpty()) {
            return configuration.getAlgorithms().stream().anyMatch(algorithm -> algorithm.getAlg() == signature.getAlgorithm());
        }

        return true;
    }

    private Signature extractSignature(final Request request) {
        String signature = null;
        if (configuration.getScheme() == HttpSignatureScheme.AUTHORIZATION) {
            // https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.section.3.1
            signature = request.headers().get(HttpHeaderNames.AUTHORIZATION);

        } else if (configuration.getScheme() == HttpSignatureScheme.SIGNATURE) {
            // https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.section.4.1
            signature = request.headers().getFirst(HTTP_HEADER_SIGNATURE);
        }

        try {
            if (signature == null) {
                return null;
            }
            if (!configuration.isStrictMode() && !signature.contains("\"")) {
                signature = convertToStrictSignature(signature);
            }
            return Signature.fromString(signature);
        } catch (Exception ex) {
            request.metrics().setMessage(ex.getMessage());
            return null;
        }
    }

    /**
     * Regular expression pattern for fields present in the Authorization field.
     * Fields value may be double-quoted strings, e.g. algorithm="hs2019"
     * Some fields may be numerical values without double-quotes, e.g. created=123456
     * see https://github.com/tomitribe/http-signatures-java/blob/3a84217890d9c7d93d42585c4c9d86225d69f4ff/src/main/java/org/tomitribe/auth/signatures/Signature.java
     */
    private static final Pattern RFC_2617_PARAM_NON_STRICT = Pattern.compile("(?<key>\\w+)=((?<stringValue>.*?)($|,))");
    private String convertToStrictSignature(String signature) {
        final Matcher matcher = RFC_2617_PARAM_NON_STRICT.matcher(signature);
        Map<String, String> kv = new HashMap<>();
        while (matcher.find()) {
            final String key = matcher.group("key").toLowerCase();
            String value = matcher.group("stringValue");
            try {
                Long.parseLong(value);
                kv.put(key, value);
            } catch (NumberFormatException e) {
                kv.put(key, "\"" + value + "\"");
            }
        }
        String newSignature ="Signature " + kv.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((a,b)-> a+","+b)
                .get();
        return newSignature;
    }
}
