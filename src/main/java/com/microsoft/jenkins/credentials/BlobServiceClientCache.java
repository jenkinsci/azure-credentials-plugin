/*
Copyright 2024 Tim Jacomb

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package com.microsoft.jenkins.credentials;

import com.azure.core.credential.TokenCredential;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.microsoft.azure.util.AzureBaseCredentials;
import com.microsoft.azure.util.AzureCredentialUtil;
import com.microsoft.azure.util.AzureCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.time.Duration;
import java.util.Objects;

public final class BlobServiceClientCache {

    private static final long MAX_SIZE = 50L;
    private static final Duration EXPIRE_AFTER = Duration.ofHours(24);

    private static final LoadingCache<BlobServiceClientCache.CacheKey, BlobServiceClient> CACHE = Caffeine.newBuilder()
            .maximumSize(MAX_SIZE)
            .expireAfterWrite(EXPIRE_AFTER)
            .build(BlobServiceClientCache::createClient);

    private BlobServiceClientCache() {}

    @CheckForNull
    public static BlobServiceClient get(String credentialsId, String blobServiceEndpoint) {
        return CACHE.get(new CacheKey(credentialsId, blobServiceEndpoint));
    }

    /**
     * Used to notify when credentials change, e.g. service principal secret updated.
     */
    public static void invalidateCache() {
        // Could be optimised to only invalidate specific keys in the future if required
        CACHE.invalidateAll();
    }

    private static BlobServiceClient createClient(CacheKey key) {
        AzureBaseCredentials credential = AzureCredentialUtil.getCredential(null, key.credentialsId);
        if (credential == null) {
            return null;
        }

        TokenCredential tokenCredential = AzureCredentials.getTokenCredential(credential);

        return new BlobServiceClientBuilder()
                .credential(tokenCredential)
                .endpoint(key.blobServiceEndpoint)
                .httpClient(HttpClientRetriever.get())
                .buildClient();
    }

    private static class CacheKey {
        private final String credentialsId;
        private final String blobServiceEndpoint;

        CacheKey(String credentialsId, String blobServiceEndpoint) {
            this.credentialsId = credentialsId;
            this.blobServiceEndpoint = blobServiceEndpoint;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            CacheKey cacheKey = (CacheKey) o;
            return Objects.equals(credentialsId, cacheKey.credentialsId)
                    && Objects.equals(blobServiceEndpoint, cacheKey.blobServiceEndpoint);
        }

        @Override
        public int hashCode() {
            return Objects.hash(credentialsId, blobServiceEndpoint);
        }
    }
}
