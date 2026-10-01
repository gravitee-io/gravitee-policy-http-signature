/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.httpsignature;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import io.gravitee.common.http.HttpMethod;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.el.spel.SpelTemplateEngineFactory;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.httpsignature.configuration.Algorithm;
import io.gravitee.policy.httpsignature.configuration.HttpSignaturePolicyConfiguration;
import io.gravitee.policy.httpsignature.configuration.HttpSignatureScheme;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class HttpSignaturePolicyTest {

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain chain;

    @Mock
    private ExecutionContext context;

    @Mock
    private HttpSignaturePolicyConfiguration configuration;

    @Before
    public void init() {
        when(context.getTemplateEngine()).thenReturn(new SpelTemplateEngineFactory().templateEngine());
    }

    @Test
    public void shouldNotContinueRequestProcessing_noSignature() {
        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_noSignature_authorizationScheme() {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.AUTHORIZATION);

        HttpHeaders headers = HttpHeaders.create().set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, "dummy-signature");
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_noSignature_signatureScheme() {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);

        HttpHeaders headers = HttpHeaders.create().set(HttpHeaderNames.AUTHORIZATION, "Signature: dummy-signature");
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void test() throws IOException {
        final String s =
            "Signature keyId=\"rsa-key-1\",created=1631088457,expires=1631088517,000,algorithm=\"hmac-sha256\",headers=\"host (created) (expires)\",signature=\"I91PyHGv5DnzZ9pZEn5GWh5sphbdD0L1BtRl+RzkNBs=\"";
        final Signature signature = new Signature(
            "keyid",
            null,
            org.tomitribe.auth.signatures.Algorithm.HMAC_SHA384,
            null,
            null,
            Arrays.asList("(created)", "(expires)"),
            300000000L,
            1631088457L,
            1631088517123L
        );

        final Key key = new SecretKeySpec("secret".getBytes(), org.tomitribe.auth.signatures.Algorithm.HMAC_SHA384.getJvmName());
        final Signer signer = new Signer(key, signature);

        final Signature result = signer.sign("GET", "/api", new HashMap<>());
        final String signingString = signer.createSigningString("GET", "/api", new HashMap<>(), 1631088457L, 1631088517123L);

        //        Signature.fromString("Signature keyId=\"keyid\",created=1631089969,expires=1631289972,583,algorithm=\"hmac-sha384\",headers=\"(created) (expires)\",signature=\"mMBK8eDyD0ZbRbP5ob3b4KmbAmXZAZ4MHWOysPHNcQNxVESjEVz+zc1NvED+gjE3\"").toString();

        final String sResult = result.toString();

        final Signature result2 = Signature.fromString(sResult);

        Assert.assertEquals(sResult, result2.toString());
    }

    @Test
    public void shouldNotContinueRequestProcessing_enforceAlgorithm_unexpectedAlgorithm() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA512));

        HttpHeaders headers = HttpHeaders.create();
        when(request.headers()).thenReturn(headers);
        headers.set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_enforceAlgorithm_expectedAlgorithm() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.getAlgorithms()).thenReturn(Arrays.asList(Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA512));

        HttpHeaders headers = HttpHeaders.create().set(HttpHeaderNames.HOST, "gravitee.io");
        headers.set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldContinueRequestProcessing_encodeSignature() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.isDecodeSignature()).thenReturn(true);
        when(configuration.getAlgorithms()).thenReturn(Arrays.asList(Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA512));

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", true))
            .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldContinueRequestProcessing_noAlgorithmEnforced() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getSecret()).thenReturn("my-passphrase");

        HttpHeaders headers = HttpHeaders.create().set(HttpHeaderNames.HOST, "gravitee.io");
        headers.set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_invalidFormat() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.AUTHORIZATION);

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpHeaderNames.AUTHORIZATION, "Signature keyId=gravitee,algorithm=hmac-sha1,signature=HU91saJzo6wdLVtS0%2F4VXINpGXM%3D");

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessingNonStrict_invalidFormat() throws IOException {
        when(configuration.isStrictMode()).thenReturn(Boolean.FALSE);
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.getAlgorithms()).thenReturn(Arrays.asList(Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA512));

        String sig = generateSignature("my-passphrase", false);
        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, sig.replaceAll("\"", ""));

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldContinueRequestProcessing_noHeaderEnforced() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Arrays.asList(Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA512));
        when(configuration.getSecret()).thenReturn("my-passphrase");

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_enforceHeaders_missingHeader() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList("X-Gravitee-Header"));

        HttpHeaders headers = HttpHeaders.create().set(
            HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
            generateSignature("my-passphrase", false)
        );
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_enforceHeaders_withoutHeaderInRequest() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));

        HttpHeaders headers = HttpHeaders.create().set(
            HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
            generateSignature("my-passphrase", false)
        );
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_enforceHeaders_withHeaderInRequest() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));
        when(configuration.getSecret()).thenReturn("my-passphrase");

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false))
            .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_validateHeaders() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));

        HttpHeaders headers = HttpHeaders.create().set(
            HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
            generateSignature("my-passphrase", false)
        );

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_withClockSkew() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.getClockSkew()).thenReturn(30L);

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false))
            .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_withClockSkew_staleDateHeader() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getClockSkew()).thenReturn(30L);
        stubValidSignatureVerification();

        // Signed years ago: a captured request replayed today must not still validate.
        String staleDate = "Wed, 03 Feb 2021 17:06:35 GMT";

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpHeaderNames.DATE, staleDate)
            .set(
                HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
                generateSignatureWithHeaders("my-passphrase", Arrays.asList("date"), staleDate)
            );

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_withClockSkew_freshDateHeader() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.getClockSkew()).thenReturn(30L);

        String freshDate = java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(
            java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC)
        );

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpHeaderNames.DATE, freshDate)
            .set(
                HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
                generateSignatureWithHeaders("my-passphrase", Arrays.asList("date"), freshDate)
            );

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_withClockSkew_staleCreatedWithoutExpires() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getClockSkew()).thenReturn(30L);
        stubValidSignatureVerification();

        // (created) three days ago, no (expires): must not be treated as eternally valid.
        long staleCreated = System.currentTimeMillis() - java.time.Duration.ofDays(3).toMillis();

        final Signature signature = new Signature(
            "key-alias",
            org.tomitribe.auth.signatures.Algorithm.HMAC_SHA256.name(),
            null,
            Arrays.asList("(created)")
        );
        final Key key = new SecretKeySpec("my-passphrase".getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);
        String compSignature = signer.sign("GET", "/my/api", new HashMap<>(), staleCreated, null).toString();

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, compSignature);

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_withClockSkew_staleDateHeader_unsignedCreatedAppended() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getClockSkew()).thenReturn(30L);
        stubValidSignatureVerification();

        String staleDate = "Wed, 03 Feb 2021 17:06:35 GMT";
        long nowSeconds = System.currentTimeMillis() / 1000L;

        // A replayed 'Date'-only signature with an unsigned, fresh 'created' appended must not skip the 'Date' check.
        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpHeaderNames.DATE, staleDate)
            .set(
                HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
                generateSignatureWithHeaders("my-passphrase", Arrays.asList("date"), staleDate) + ",created=" + nowSeconds
            );

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_withClockSkew_staleDateHeader_unsignedExpiresAppended() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getClockSkew()).thenReturn(30L);
        stubValidSignatureVerification();

        String staleDate = "Wed, 03 Feb 2021 17:06:35 GMT";
        long futureSeconds = System.currentTimeMillis() / 1000L + 3600;

        // A replayed 'Date'-only signature with an unsigned, future 'expires' appended must not skip the 'Date' check.
        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpHeaderNames.DATE, staleDate)
            .set(
                HttpSignaturePolicy.HTTP_HEADER_SIGNATURE,
                generateSignatureWithHeaders("my-passphrase", Arrays.asList("date"), staleDate) + ",expires=" + futureSeconds
            );

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_withClockSkew_signedExpiresWindowLongerThanSkew() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getClockSkew()).thenReturn(30L);
        stubValidSignatureVerification();

        // Signed 60s ago with a 5-minute validity window: older than the skew, but still within its own (expires).
        long nowSeconds = System.currentTimeMillis() / 1000L;
        long created = (nowSeconds - 60) * 1000L;
        long expires = (nowSeconds + 240) * 1000L;

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpHeaderNames.HOST, "gravitee.io")
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignatureWithCreatedAndExpires("my-passphrase", created, expires));

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
        verify(chain, never()).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldNotContinueRequestProcessing_invalidSecret() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));
        when(configuration.getSecret()).thenReturn("wrong-passphrase");

        HttpHeaders headers = HttpHeaders.create()
            .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false))
            .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_invalidSignature() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.AUTHORIZATION);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));
        when(configuration.getSecret()).thenReturn("wrong-passphrase");

        HttpHeaders headers = HttpHeaders.create()
            .set(
                HttpHeaderNames.AUTHORIZATION,
                "Signature keyId=\"key-alias\",created=1612796632,algorithm=\"hmac-sha256\",headers=\"(request-target) host\",signature=\"qREl8Za0cQwFlcCKo5HCdfIf1tFp3m5xS3O0L0+3MM4=\""
            )
            .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    /**
     * Stubs everything the signature verification needs, so that a rejection can only come from the
     * validity date checks. Lenient because those checks reject the request before the stubs are used.
     */
    private void stubValidSignatureVerification() {
        lenient().when(configuration.getSecret()).thenReturn("my-passphrase");
        lenient().when(request.method()).thenReturn(HttpMethod.GET);
        lenient().when(request.path()).thenReturn("/my/api");
    }

    /**
     * Builds the Signature header by hand so that 'expires' is written as whole seconds, independently of the
     * default locale used by {@link Signature#toString()}.
     */
    private String generateSignatureWithCreatedAndExpires(final String passphrase, final long created, final long expires)
        throws IOException {
        final Signature signature = new Signature("key-alias", "hmac-sha256", null, Arrays.asList("(created)", "(expires)"));
        final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);
        final Signature signed = signer.sign("get", "/my/api", new HashMap<>(), created, expires);

        return String.format(
            "Signature keyId=\"key-alias\",created=%d,expires=%d,algorithm=\"hmac-sha256\",headers=\"(created) (expires)\",signature=\"%s\"",
            created / 1000L,
            expires / 1000L,
            signed.getSignature()
        );
    }

    private String generateSignatureWithHeaders(final String passphrase, final java.util.List<String> signedHeaders, final String dateValue)
        throws IOException {
        final Signature signature = new Signature("key-alias", "hmac-sha256", null, signedHeaders);
        final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");
        final Signer signer = new Signer(key, signature);

        final Map<String, String> headers = new HashMap<>();
        headers.put("Host", "gravitee.io");
        headers.put("Date", dateValue);

        return signer.sign("GET", "/my/api", headers).toString();
    }

    private String generateSignature(final String passphrase, boolean encode) throws IOException {
        final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)", "host"); // (1)
        final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256"); // (2)
        final Signer signer = new Signer(key, signature); // (3)

        final String method = "GET";

        final String uri = "/my/api";

        final Map<String, String> headers = new HashMap<>();
        headers.put("Host", "gravitee.io");
        headers.put("Date", "Wed, 03 Feb 2021 17:06:35 GMT");
        headers.put("Content-Type", "application/json");
        headers.put("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.put("Accept", "*/*");
        headers.put("Content-Length", "18");

        String compSignature = signer.sign(method, uri, headers).toString();

        int idxSign = compSignature.indexOf("signature=");
        String sSign = compSignature.substring(idxSign + 11, compSignature.length() - 1);
        if (encode) {
            compSignature = compSignature.replace(sSign, URLEncoder.encode(sSign, StandardCharsets.UTF_8));
        }

        return compSignature;
    }
}
