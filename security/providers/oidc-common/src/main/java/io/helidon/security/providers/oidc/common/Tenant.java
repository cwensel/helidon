/*
 * Copyright (c) 2023, 2025 Oracle and/or its affiliates.
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

package io.helidon.security.providers.oidc.common;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import io.helidon.common.Errors;
import io.helidon.common.LazyValue;
import io.helidon.http.ClientResponseHeaders;
import io.helidon.security.Security;
import io.helidon.security.SecurityException;
import io.helidon.security.jwt.jwk.JwkKeys;
import io.helidon.security.providers.common.OutboundTarget;
import io.helidon.security.providers.httpauth.HttpBasicAuthProvider;
import io.helidon.security.providers.httpauth.HttpBasicOutboundConfig;
import io.helidon.webclient.api.HttpClientResponse;
import io.helidon.webclient.api.WebClient;
import io.helidon.webclient.api.WebClientConfig;
import io.helidon.webclient.security.WebClientSecurity;

import jakarta.json.JsonObject;

/**
 * Holder of the tenant configuration resolved at runtime. Used for OIDC lazy loading.
 * <p>
 * JWK keys are loaded once at tenant creation. By default, keys are never refreshed.
 * When {@code jwk-cache-refresh-enabled} is set to {@code true}, keys are cached with
 * automatic refresh based on TTL. The TTL can be determined from the JWKS endpoint's
 * {@code Cache-Control: max-age} header (when {@code jwk-honor-cache-control} is {@code true}),
 * or from the configured {@code jwk-cache-default-ttl-minutes}. TTL values are constrained
 * by configurable minimum and maximum bounds.
 * <p>
 * When JWT signature validation fails and {@code jwk-refresh-on-validation-failure} is
 * enabled, the system fetches fresh JWK keys and retries validation once to handle
 * key rotation scenarios.
 */
public class Tenant {

    private static final System.Logger LOGGER = System.getLogger(Tenant.class.getName());

    private final TenantConfig tenantConfig;
    private final URI tokenEndpointUri;
    private final String authorizationEndpointUri;
    private final URI logoutEndpointUri;
    private final String issuer;
    private final WebClient appWebClient;
    private final WebClient generalWebClient;
    private final JwkKeys signJwk;
    private final URI introspectUri;
    private final String serverType;
    private final URI identityUri;
    private final AtomicReference<LazyValue<CachedJwkKeys>> cachedSignJwkRef = new AtomicReference<>();
    private Clock clock = Clock.systemUTC();
    private Supplier<JwkKeys> jwkRefreshSupplier;
    private boolean hasCustomRefreshSupplier = false;

    private Tenant(TenantConfig tenantConfig,
                   URI tokenEndpointUri,
                   URI authorizationEndpointUri,
                   URI logoutEndpointUri,
                   String issuer,
                   WebClient appWebClient,
                   WebClient generalWebClient,
                   JwkKeys signJwk,
                   URI introspectUri,
                   String serverType,
                   URI identityUri) {
        this.tenantConfig = tenantConfig;
        this.tokenEndpointUri = tokenEndpointUri;
        this.authorizationEndpointUri = authorizationEndpointUri.toString();
        this.logoutEndpointUri = logoutEndpointUri;
        this.issuer = issuer;
        this.appWebClient = appWebClient;
        this.generalWebClient = generalWebClient;
        this.signJwk = signJwk;
        this.introspectUri = introspectUri;
        this.serverType = serverType;
        this.identityUri = identityUri;
        this.jwkRefreshSupplier = () -> refreshAndCacheJwkKeys().keys;
    }

    /**
     * Create new instance and resolve all the metadata related values.
     *
     * @param oidcConfig overall OIDC config
     * @param tenantConfig tenant config
     * @return new instance with resolved OIDC metadata
     */
    public static Tenant create(OidcConfig oidcConfig, TenantConfig tenantConfig) {
        WebClient webClient = oidcConfig.generalWebClient();

        Errors.Collector collector = Errors.collector();

        URI identityUri = tenantConfig.identityUri();
        OidcMetadata oidcMetadata = OidcMetadata.builder()
                .remoteEnabled(tenantConfig.useWellKnown())
                .json(tenantConfig.oidcMetadata())
                .webClient(webClient)
                .identityUri(identityUri)
                .collector(collector)
                .build();

        String serverType = tenantConfig.serverType();
        String metaKey = resolveMetaKey("token_endpoint", serverType, identityUri);
        URI tokenEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                            tenantConfig.tenantTokenEndpointUri().orElse(null),
                                                            metaKey,
                                                            "/oauth2/v1/token");

        URI authorizationEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                                    tenantConfig.authorizationEndpoint().orElse(null),
                                                                    "authorization_endpoint",
                                                                    "/oauth2/v1/authorize");

        metaKey = resolveMetaKey("end_session_endpoint", serverType, identityUri);
        URI logoutEndpointUri = oidcMetadata.getOidcEndpoint(collector,
                                                             tenantConfig.tenantLogoutEndpointUri().orElse(null),
                                                             metaKey,
                                                             "oauth2/v1/userlogout");

        String issuer = tenantConfig.tenantIssuer()
                .or(() -> oidcMetadata.getString("issuer"))
                .orElse(null);

        collector.collect().checkValid();
        WebClientConfig.Builder webClientBuilder = oidcConfig.webClientBuilderSupplier().get();

        if (tenantConfig.tokenEndpointAuthentication() == OidcConfig.ClientAuthentication.CLIENT_SECRET_BASIC) {

            HttpBasicAuthProvider httpBasicAuth = HttpBasicAuthProvider.builder()
                    .addOutboundTarget(OutboundTarget.builder("oidc")
                                               .addHost("*")
                                               .customObject(HttpBasicOutboundConfig.class,
                                                             HttpBasicOutboundConfig.create(tenantConfig.clientId(),
                                                                                            tenantConfig.clientSecret()))
                                               .build())
                    .build();
            Security tokenOutboundSecurity = Security.builder()
                    .addOutboundSecurityProvider(httpBasicAuth)
                    .build();

            webClientBuilder.addService(WebClientSecurity.create(tokenOutboundSecurity));
        }

        WebClient appWebClient = webClientBuilder.build();

        JwkKeys signJwk = tenantConfig.tenantSignJwk().orElseGet(() -> {
            if (tenantConfig.validateJwtWithJwk()) {
                // not configured - use default location
                String jwksMetaKey = resolveMetaKey("jwks_uri", serverType, identityUri);
                URI jwkUri = oidcMetadata.getOidcEndpoint(collector,
                                                          null,
                                                          jwksMetaKey,
                                                          null);
                if (jwkUri != null) {
                    if ("idcs".equals(serverType)) {
                        return IdcsSupport.signJwk(appWebClient,
                                                   webClient,
                                                   tokenEndpointUri,
                                                   jwkUri,
                                                   tenantConfig.clientTimeout(),
                                                   tenantConfig);
                    } else {
                        return JwkKeys.builder()
                                .json(webClient.get()
                                              .uri(jwkUri)
                                              .requestEntity(JsonObject.class))
                                .build();
                    }
                }
            }
            return JwkKeys.builder().build();
        });
        URI introspectUri = tenantConfig.tenantIntrospectUri().orElse(null);
        if (!tenantConfig.validateJwtWithJwk()) {
            metaKey = resolveMetaKey("introspection_endpoint", serverType, identityUri);
            introspectUri = oidcMetadata.getOidcEndpoint(collector,
                                                         introspectUri,
                                                         metaKey,
                                                         "/oauth2/v1/introspect");
        }
        return new Tenant(tenantConfig,
                          tokenEndpointUri,
                          authorizationEndpointUri,
                          logoutEndpointUri,
                          issuer,
                          appWebClient,
                          webClient,
                          signJwk,
                          introspectUri,
                          serverType,
                          identityUri);
    }

    private static String resolveMetaKey(String metaKey, String serverType, URI identityUri) {
        if ("idcs".equals(serverType) && identityUri.toString().contains(".secure.")) {
            //when server is IDCS and URI has ".secure." defined, we know we are using MTLS and need to obtain
            //secured endpoint also.
            return "secure_" + metaKey;
        }
        return metaKey;
    }

    /**
     * Provided tenant configuration.
     *
     * @return tenant configuration
     */
    public TenantConfig tenantConfig() {
        return tenantConfig;
    }

    /**
     * Token endpoint URI.
     *
     * @return endpoint URI
     */
    public URI tokenEndpointUri() {
        return tokenEndpointUri;
    }

    /**
     * Authorization endpoint.
     *
     * @return authorization endpoint uri as a string
     */
    public String authorizationEndpointUri() {
        return authorizationEndpointUri;
    }

    /**
     * Logout endpoint on OIDC server.
     *
     * @return URI of the logout endpoint
     */
    public URI logoutEndpointUri() {
        return logoutEndpointUri;
    }

    /**
     * Token issuer.
     *
     * @return token issuer
     */
    public String issuer() {
        return issuer;
    }

    /**
     * Client with configured proxy and security.
     *
     * @return client for communicating with OIDC identity server
     */
    public WebClient appWebClient() {
        return appWebClient;
    }

    /**
     * JWK used for signature validation.
     * Returns cached keys if valid, otherwise refreshes from remote endpoint.
     *
     * @return set of keys used to verify tokens
     */
    public JwkKeys signJwk() {
        return signJwk(false);
    }

    /**
     * JWK used for signature validation.
     *
     * @param forceRefresh if true, bypass cache and fetch fresh keys
     * @return set of keys used to verify tokens
     */
    public JwkKeys signJwk(boolean forceRefresh) {
        if (!tenantConfig.validateJwtWithJwk() || !tenantConfig.jwkCacheRefreshEnabled()) {
            return signJwk;
        }

        LazyValue<CachedJwkKeys> currentLazy = cachedSignJwkRef.get();

        if (currentLazy != null && !forceRefresh) {
            CachedJwkKeys cached = currentLazy.get();
            if (cached.isValid(clock)) {
                LOGGER.log(System.Logger.Level.TRACE, "JWK cache hit for tenant: " + tenantConfig.name());
                return cached.keys;
            }
        }

        if (currentLazy != null && !forceRefresh) {
            LOGGER.log(System.Logger.Level.INFO,
                    "JWK cache expired for tenant: " + tenantConfig.name() + ", refreshing from remote endpoint");
        } else if (forceRefresh) {
            LOGGER.log(System.Logger.Level.INFO,
                    "JWK force refresh triggered for tenant: " + tenantConfig.name() + ", refreshing from remote endpoint");
        }

        LazyValue<CachedJwkKeys> newLazy = LazyValue.create(this::fetchAndCacheJwkKeys);
        if (cachedSignJwkRef.compareAndSet(currentLazy, newLazy)) {
            return newLazy.get().keys;
        } else {
            return cachedSignJwkRef.get().get().keys;
        }
    }

    /**
     * Introspection endpoint URI.
     *
     * @return introspection endpoint URI
     */
    public URI introspectUri() {
        if (introspectUri == null) {
            throw new SecurityException("Introspect URI is not configured when using validate with JWK.");
        }
        return introspectUri;
    }

    boolean isCacheValid() {
        LazyValue<CachedJwkKeys> currentLazy = cachedSignJwkRef.get();
        return currentLazy != null && currentLazy.get().isValid(clock);
    }

    void clock(Clock clock) {
        this.clock = clock;
    }

    void jwkRefreshSupplier(Supplier<JwkKeys> supplier) {
        this.jwkRefreshSupplier = supplier;
        this.hasCustomRefreshSupplier = true;
    }

    void cachedJwk(CachedJwkKeys cached) {
        cachedSignJwkRef.set(LazyValue.create(() -> cached));
    }

    private CachedJwkKeys fetchAndCacheJwkKeys() {
        if (hasCustomRefreshSupplier) {
            JwkKeys keys = jwkRefreshSupplier.get();
            return cacheJwkWithExpiry(keys, null);
        }
        return refreshAndCacheJwkKeys();
    }

    private CachedJwkKeys refreshAndCacheJwkKeys() {
        OidcMetadata oidcMetadata = OidcMetadata.builder()
                .remoteEnabled(tenantConfig.useWellKnown())
                .json(tenantConfig.oidcMetadata())
                .webClient(generalWebClient)
                .identityUri(identityUri)
                .collector(Errors.collector())
                .build();

        String jwksMetaKey = resolveMetaKey("jwks_uri", serverType, identityUri);
        URI jwkUri = oidcMetadata.getOidcEndpoint(Errors.collector(), null, jwksMetaKey, null);

        if (jwkUri != null) {
            if ("idcs".equals(serverType)) {
                JwkKeys keys = IdcsSupport.signJwk(appWebClient,
                                                   generalWebClient,
                                                   tokenEndpointUri,
                                                   jwkUri,
                                                   tenantConfig.clientTimeout(),
                                                   tenantConfig);
                return cacheJwkWithExpiry(keys, null);
            } else {
                try (HttpClientResponse response = generalWebClient.get()
                        .uri(jwkUri)
                        .request()) {

                    JsonObject jwkJson = response.as(JsonObject.class);
                    JwkKeys keys = JwkKeys.create(jwkJson);
                    return cacheJwkWithExpiry(keys, response.headers());
                }
            }
        }
        JwkKeys emptyKeys = JwkKeys.builder().build();
        return cacheJwkWithExpiry(emptyKeys, null);
    }

    CachedJwkKeys cacheJwkWithExpiry(JwkKeys keys, ClientResponseHeaders headers) {
        Duration maxAge = tenantConfig.jwkCacheDefaultTtl();

        if (tenantConfig.jwkHonorCacheControl()
                && headers != null
                && headers.contains(io.helidon.http.HeaderNames.CACHE_CONTROL)) {
            String cacheControl = headers.get(io.helidon.http.HeaderNames.CACHE_CONTROL).values();
            if (cacheControl.contains("max-age=")) {
                try {
                    String value = cacheControl.substring(cacheControl.indexOf("max-age=") + 8)
                            .split("[,;]")[0]
                            .trim();
                    Duration headerMaxAge = Duration.ofSeconds(Long.parseLong(value));

                    if (headerMaxAge.compareTo(tenantConfig.jwkCacheMinTtl()) < 0) {
                        maxAge = tenantConfig.jwkCacheMinTtl();
                        LOGGER.log(System.Logger.Level.DEBUG,
                                  "JWK Cache-Control max-age below minimum, using min: "
                                          + maxAge.toMinutes() + " minutes");
                    } else if (headerMaxAge.compareTo(tenantConfig.jwkCacheMaxTtl()) > 0) {
                        maxAge = tenantConfig.jwkCacheMaxTtl();
                        LOGGER.log(System.Logger.Level.DEBUG,
                                  "JWK Cache-Control max-age above maximum, using max: "
                                          + maxAge.toMinutes() + " minutes");
                    } else {
                        maxAge = headerMaxAge;
                        LOGGER.log(System.Logger.Level.DEBUG,
                                  "Using JWK Cache-Control max-age: " + maxAge.toSeconds() + " seconds");
                    }
                } catch (NumberFormatException | IndexOutOfBoundsException e) {
                    LOGGER.log(System.Logger.Level.WARNING,
                              "Failed to parse Cache-Control max-age, using default TTL", e);
                }
            }
        }

        Instant expiresAt = Instant.now(clock).plus(maxAge);
        CachedJwkKeys cached = new CachedJwkKeys(keys, expiresAt, clock);

        LOGGER.log(System.Logger.Level.DEBUG,
                  "JWK keys cached for tenant: " + tenantConfig.name() + ", expires at: " + expiresAt);

        return cached;
    }

    private static final class CachedJwkKeys {

        private static final Duration DEFAULT_BUFFER_TIME = Duration.ofSeconds(30);
        private final JwkKeys keys;
        private final Instant expiresAtBuffered;

        CachedJwkKeys(JwkKeys keys, Instant expiresAt, Clock clock) {
            this.keys = keys;
            Instant now = Instant.now(clock);
            Instant buffered = expiresAt.minus(DEFAULT_BUFFER_TIME);
            if (buffered.isBefore(now)) {
                LOGGER.log(System.Logger.Level.WARNING,
                          "JWK cache TTL is too short (less than buffer time of " + DEFAULT_BUFFER_TIME.toSeconds()
                                  + " seconds). Cache will expire immediately. "
                                  + "Consider increasing jwk-cache-default-ttl-minutes.");
                this.expiresAtBuffered = now;
            } else {
                this.expiresAtBuffered = buffered;
            }
        }

        private boolean isValid(Clock clock) {
            return Instant.now(clock).isBefore(expiresAtBuffered);
        }
    }
}
