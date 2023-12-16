/*
Copyright 2021 Tim Jacomb

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

import com.azure.resourcemanager.AzureResourceManager;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import java.time.Duration;
import java.util.Objects;

public final class AzureResourceManagerCache {

    private static final long MAX_SIZE = 50L;
    private static final Duration EXPIRE_AFTER = Duration.ofHours(24);

    private static final LoadingCache<AzureResourceManagerCache.CacheKey, AzureResourceManager> CACHE =
            Caffeine.newBuilder()
                    .maximumSize(MAX_SIZE)
                    .expireAfterWrite(EXPIRE_AFTER)
                    .build(AzureResourceManagerCache::createClient);

    private AzureResourceManagerCache() {}

    @CheckForNull
    public static AzureResourceManager get(String credentialsId) {
        return CACHE.get(new CacheKey(credentialsId));
    }

    @CheckForNull
    public static AzureResourceManager get(String credentialsId, String subscriptionId) {
        return CACHE.get(new CacheKey(credentialsId, subscriptionId));
    }

    /**
     * Used to notify when credentials change, e.g. service principal secret updated.
     */
    public static void invalidateCache() {
        // Could be optimised to only invalidate specific keys in the future if required
        CACHE.invalidateAll();
    }

    private static AzureResourceManager createClient(CacheKey key) {
        return AzureResourceManagerRetriever.getClient(key.credentialsId, key.subscriptionId);
    }

    private static class CacheKey {
        private final String credentialsId;
        private final String subscriptionId;

        CacheKey(String credentialsId) {
            this.credentialsId = credentialsId;
            this.subscriptionId = null;
        }

        CacheKey(String credentialsId, String subscriptionId) {
            this.credentialsId = credentialsId;
            this.subscriptionId = subscriptionId;
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
            return credentialsId.equals(cacheKey.credentialsId)
                    && Objects.equals(subscriptionId, cacheKey.subscriptionId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(credentialsId, subscriptionId);
        }
    }
}
