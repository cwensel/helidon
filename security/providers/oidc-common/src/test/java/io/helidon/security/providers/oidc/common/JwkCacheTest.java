/*
 * Copyright (c) 2025 Oracle and/or its affiliates.
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
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicInteger;

import io.helidon.http.ClientResponseHeaders;
import io.helidon.http.HeaderNames;
import io.helidon.http.WritableHeaders;
import io.helidon.security.jwt.jwk.JwkKeys;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class JwkCacheTest {

    private static final Instant BASE_TIME = Instant.parse("2025-01-01T00:00:00Z");

    @Test
    void testCacheRefreshDisabledByDefault() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .build();

        assertThat("Cache refresh should be disabled by default",
                  config.jwkCacheRefreshEnabled(), is(false));
    }

    @Test
    void testCacheExpirationWithMockClock() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .jwkCacheRefreshEnabled(true)
                .jwkCacheDefaultTtl(Duration.ofSeconds(31))
                .build();

        OidcConfig oidcConfig = OidcConfig.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .frontendUri("http://localhost")
                .oidcMetadataWellKnown(false)
                .build();

        Tenant tenant = Tenant.create(oidcConfig, config);
        Clock mockClock = Clock.fixed(BASE_TIME, ZoneId.of("UTC"));
        tenant.clock(mockClock);

        JwkKeys testKeys = JwkKeys.builder().build();
        tenant.cachedJwk(tenant.cacheJwkWithExpiry(testKeys, null));

        assertThat("Cache should be valid initially", tenant.isCacheValid(), is(true));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(2), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should expire after advancing clock", tenant.isCacheValid(), is(false));
    }

    @Test
    void testCacheControlMaxAgeWithClock() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .jwkCacheRefreshEnabled(true)
                .jwkCacheMinTtl(Duration.ofSeconds(60))
                .jwkCacheMaxTtl(Duration.ofSeconds(180))
                .jwkCacheDefaultTtl(Duration.ofSeconds(120))
                .build();

        OidcConfig oidcConfig = OidcConfig.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .frontendUri("http://localhost")
                .oidcMetadataWellKnown(false)
                .build();

        Tenant tenant = Tenant.create(oidcConfig, config);
        Clock mockClock = Clock.fixed(BASE_TIME, ZoneId.of("UTC"));
        tenant.clock(mockClock);

        JwkKeys testKeys = JwkKeys.builder().build();

        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(HeaderNames.CACHE_CONTROL, "public, max-age=90, immutable");
        ClientResponseHeaders responseHeaders = ClientResponseHeaders.create(headers);

        tenant.cachedJwk(tenant.cacheJwkWithExpiry(testKeys, responseHeaders));
        assertThat("Cache should be valid with parsed Cache-Control", tenant.isCacheValid(), is(true));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(61), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should expire after max-age minus buffer", tenant.isCacheValid(), is(false));
    }

    @Test
    void testCacheMinMaxBoundsWithClock() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .jwkCacheRefreshEnabled(true)
                .jwkCacheMinTtl(Duration.ofSeconds(60))
                .jwkCacheMaxTtl(Duration.ofSeconds(120))
                .jwkCacheDefaultTtl(Duration.ofSeconds(90))
                .build();

        OidcConfig oidcConfig = OidcConfig.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .frontendUri("http://localhost")
                .oidcMetadataWellKnown(false)
                .build();

        Tenant tenant = Tenant.create(oidcConfig, config);
        Clock mockClock = Clock.fixed(BASE_TIME, ZoneId.of("UTC"));
        tenant.clock(mockClock);

        JwkKeys testKeys = JwkKeys.builder().build();
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(HeaderNames.CACHE_CONTROL, "max-age=30");
        ClientResponseHeaders responseHeaders = ClientResponseHeaders.create(headers);

        tenant.cachedJwk(tenant.cacheJwkWithExpiry(testKeys, responseHeaders));
        assertThat("Cache should use min TTL when max-age below minimum", tenant.isCacheValid(), is(true));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(25), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should still be valid before expiry (60s min - 30s buffer = 30s)",
                  tenant.isCacheValid(), is(true));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(31), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should expire after 60s min TTL minus 30s buffer",
                  tenant.isCacheValid(), is(false));
    }

    @Test
    void testActualRefreshMechanism() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .jwkCacheRefreshEnabled(true)
                .jwkCacheDefaultTtl(Duration.ofSeconds(35))
                .build();

        OidcConfig oidcConfig = OidcConfig.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .frontendUri("http://localhost")
                .oidcMetadataWellKnown(false)
                .build();

        Tenant tenant = Tenant.create(oidcConfig, config);
        Clock mockClock = Clock.fixed(BASE_TIME, ZoneId.of("UTC"));
        tenant.clock(mockClock);

        AtomicInteger fetchCount = new AtomicInteger(0);
        tenant.jwkRefreshSupplier(() -> {
            fetchCount.incrementAndGet();
            return JwkKeys.builder().build();
        });

        tenant.signJwk();
        assertThat("First call should trigger fetch", fetchCount.get(), is(1));

        tenant.signJwk();
        tenant.signJwk();
        assertThat("Cache hits should not trigger fetch", fetchCount.get(), is(1));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(10), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        tenant.signJwk();
        assertThat("Cache expired, should trigger refresh", fetchCount.get(), is(2));

        tenant.signJwk(true);
        assertThat("Force refresh should trigger fetch", fetchCount.get(), is(3));
    }

    @Test
    void testIgnoreCacheControlHeader() {
        TenantConfig config = TenantConfig.tenantBuilder()
                .name("test")
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .validateJwtWithJwk(true)
                .oidcMetadataWellKnown(false)
                .jwkCacheRefreshEnabled(true)
                .jwkHonorCacheControl(false)
                .jwkCacheDefaultTtl(Duration.ofSeconds(120))
                .build();

        OidcConfig oidcConfig = OidcConfig.builder()
                .clientId("test-client")
                .clientSecret("secret")
                .identityUri(URI.create("http://localhost"))
                .frontendUri("http://localhost")
                .oidcMetadataWellKnown(false)
                .build();

        Tenant tenant = Tenant.create(oidcConfig, config);
        Clock mockClock = Clock.fixed(BASE_TIME, ZoneId.of("UTC"));
        tenant.clock(mockClock);

        JwkKeys testKeys = JwkKeys.builder().build();
        WritableHeaders<?> headers = WritableHeaders.create();
        headers.set(HeaderNames.CACHE_CONTROL, "max-age=30");
        ClientResponseHeaders responseHeaders = ClientResponseHeaders.create(headers);

        tenant.cachedJwk(tenant.cacheJwkWithExpiry(testKeys, responseHeaders));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(35), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should still be valid using default TTL (120s - 30s = 90s), not header TTL (30s)",
                  tenant.isCacheValid(), is(true));

        mockClock = Clock.fixed(BASE_TIME.plusSeconds(91), ZoneId.of("UTC"));
        tenant.clock(mockClock);

        assertThat("Cache should expire after default TTL minus buffer",
                  tenant.isCacheValid(), is(false));
    }
}
