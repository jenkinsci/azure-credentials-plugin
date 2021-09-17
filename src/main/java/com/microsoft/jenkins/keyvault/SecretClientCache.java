package com.microsoft.jenkins.keyvault;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.secrets.SecretClient;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.microsoft.azure.util.AzureCredentials;
import java.time.Duration;
import java.util.Objects;

/**
 * Caches clients so that we don't make a fresh call to login on every secret request.
 */
public final class SecretClientCache {
    private static final long MAX_SIZE = 50L;
    private static final Duration EXPIRE_AFTER = Duration.ofMinutes(50);

    private static final LoadingCache<CacheKey, SecretClient> CACHE = Caffeine.newBuilder()
        .maximumSize(MAX_SIZE)
        .expireAfterWrite(EXPIRE_AFTER)
        .build(SecretClientCache::createClient);

    private SecretClientCache() {
    }

    public static SecretClient get(String credentialsId, String vaultUrl) {
        SecretClient secretClient = CACHE.get(new CacheKey(credentialsId, vaultUrl));
        if (secretClient == null) {
            throw new RuntimeException(String.format("client null when it should not be, vault url: "
                + "%s, credentialId: %s", vaultUrl, credentialsId));
        }
        return secretClient;
    }

    /**
     * Used to notify when credentials change, e.g. service principal secret updated.
     * We can't invalidate individual keys as when we update a credential we don't know what vault(s) it is used for.
     */
    public static void invalidateCache() {
        CACHE.invalidateAll();
    }

    private static SecretClient createClient(CacheKey key) {
        TokenCredential keyVaultCredentials = AzureCredentials.getSystemCredentialById(key.credentialsId);

        return AzureCredentials.createKeyVaultClient(
            keyVaultCredentials,
            key.vaultUrl
        );
    }

    private static class CacheKey {
        private final String credentialsId;
        private final String vaultUrl;

        CacheKey(String credentialsId, String vaultUrl) {
            this.credentialsId = credentialsId;
            this.vaultUrl = vaultUrl;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            CacheKey cacheKey = (CacheKey) o;
            return Objects.equals(credentialsId, cacheKey.credentialsId) && Objects.equals(vaultUrl, cacheKey.vaultUrl);
        }

        @Override
        public int hashCode() {
            return Objects.hash(credentialsId, vaultUrl);
        }
    }
}
