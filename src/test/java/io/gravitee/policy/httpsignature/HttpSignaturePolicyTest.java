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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

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
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_noSignature_authorizationScheme() {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.AUTHORIZATION);

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, "dummy-signature");
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_noSignature_signatureScheme() {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpHeaderNames.AUTHORIZATION, "Signature: dummy-signature");
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void test() throws IOException {
        final String s = "Signature keyId=\"rsa-key-1\",created=1631088457,expires=1631088517,000,algorithm=\"hmac-sha256\",headers=\"host (created) (expires)\",signature=\"I91PyHGv5DnzZ9pZEn5GWh5sphbdD0L1BtRl+RzkNBs=\"";
        final Signature signature = new Signature(
                "keyid",
                null,
                org.tomitribe.auth.signatures.Algorithm.HMAC_SHA384, null, null,
                Arrays.asList("(created)", "(expires)"), 300000000L, 1631088457L,
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
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldContinueRequestProcessing_enforceAlgorithm_expectedAlgorithm() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getSecret()).thenReturn("my-passphrase");
        when(configuration.getAlgorithms()).thenReturn(Arrays.asList(Algorithm.HMAC_SHA256, Algorithm.HMAC_SHA512));

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpHeaderNames.HOST, "gravitee.io");
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

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpHeaderNames.HOST, "gravitee.io");
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
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
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

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_enforceHeaders_withoutHeaderInRequest() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.SIGNATURE);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));
        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
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

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpSignaturePolicy.HTTP_HEADER_SIGNATURE, generateSignature("my-passphrase", false));

        when(request.headers()).thenReturn(headers);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
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
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    @Test
    public void shouldNotContinueRequestProcessing_invalidSignature() throws IOException {
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.AUTHORIZATION);
        when(configuration.getAlgorithms()).thenReturn(Collections.singletonList(Algorithm.HMAC_SHA256));
        when(configuration.getEnforceHeaders()).thenReturn(Collections.singletonList(HttpHeaderNames.HOST));
        when(configuration.getSecret()).thenReturn("wrong-passphrase");

        HttpHeaders headers = HttpHeaders.create()
                .set(HttpHeaderNames.AUTHORIZATION, "Signature keyId=\"key-alias\",created=1612796632,algorithm=\"hmac-sha256\",headers=\"(request-target) host\",signature=\"qREl8Za0cQwFlcCKo5HCdfIf1tFp3m5xS3O0L0+3MM4=\"")
                .set(HttpHeaderNames.HOST, "gravitee.io");

        when(request.headers()).thenReturn(headers);
        when(request.method()).thenReturn(HttpMethod.GET);

        new HttpSignaturePolicy(configuration).onRequest(request, response, context, chain);

        verify(chain, never()).doNext(request, response);
        verify(chain, times(1)).failWith(argThat(
                result -> result.statusCode() == HttpStatusCode.UNAUTHORIZED_401));
    }

    private String generateSignature(final String passphrase, boolean encode) throws IOException {
        final Signature signature = new Signature("key-alias", "hmac-sha256", null, "(request-target)", "host"); // (1)
        final Key key = new SecretKeySpec(passphrase.getBytes(), "HmacSHA256");	 // (2)
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
        String sSign = compSignature.substring(idxSign+11, compSignature.length()-1);
        if (encode) {
            compSignature = compSignature.replace(sSign, URLEncoder.encode(sSign, StandardCharsets.UTF_8));
        }

        return compSignature;
    }
}
