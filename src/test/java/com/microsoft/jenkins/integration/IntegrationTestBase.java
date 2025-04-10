/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.integration;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.Region;
import com.azure.core.management.exception.ManagementException;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Timeout;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
@Timeout(value = 20, unit = TimeUnit.MINUTES)
public abstract class IntegrationTestBase {

    protected static JenkinsRule j;

    protected static class TestEnvironment {
        private static final String ENV_PREFIX = "AZURE_CREDENTIALS_TEST_";
        public final String subscriptionId;
        public final String clientId;
        public final String clientSecret;
        public final String tenantId;
        public final String resourceGroup;
        public final Region region;

        TestEnvironment() {
            this.subscriptionId = TestEnvironment.loadFromEnv(ENV_PREFIX + "SUBSCRIPTION_ID");
            this.clientId = TestEnvironment.loadFromEnv(ENV_PREFIX + "CLIENT_ID");
            this.clientSecret = TestEnvironment.loadFromEnv(ENV_PREFIX + "CLIENT_SECRET");
            this.tenantId = TestEnvironment.loadFromEnv(ENV_PREFIX + "TENANT_ID");
            this.resourceGroup = TestEnvironment.loadFromEnv(
                    ENV_PREFIX + "RESOURCE_GROUP_PREFIX",
                    "azure-credentials-tst-" + TestEnvironment.GenerateRandomString(16));
            this.region =
                    Region.fromName(TestEnvironment.loadFromEnv(ENV_PREFIX + "REGION", Region.ASIA_SOUTHEAST.name()));
        }

        private static String loadFromEnv(final String name) {
            return TestEnvironment.loadFromEnv(name, "");
        }

        private static String loadFromEnv(final String name, final String defaultValue) {
            final String value = System.getenv(name);
            if (value == null || value.isEmpty()) {
                return defaultValue;
            } else {
                return value;
            }
        }

        public static String GenerateRandomString(int length) {
            String uuid = UUID.randomUUID().toString();
            return uuid.replaceAll("[^a-z0-9]", "a").substring(0, length);
        }
    }

    protected static TestEnvironment testEnv = null;

    @BeforeAll
    static void setUp(JenkinsRule rule) {
        j = rule;
        if (testEnv == null) {
            testEnv = new TestEnvironment();
        }
    }

    @AfterAll
    static void tearDown() {
        try {
            final AzureResourceManager azureClient = getAzureClient();
            azureClient.resourceGroups().deleteByNameAsync(testEnv.resourceGroup);
        } catch (ManagementException e) {
            if (e.getResponse().getStatusCode() != 404) {
                throw e;
            }
        }
    }

    protected static AzureResourceManager getAzureClient() {
        final TokenCredential credential = new ClientSecretCredentialBuilder()
                .clientId(testEnv.clientId)
                .clientSecret(testEnv.clientSecret)
                .tenantId(testEnv.tenantId)
                .build();

        AzureProfile profile = new AzureProfile(AzureEnvironment.AZURE);

        return AzureResourceManager.authenticate(credential, profile).withSubscription(testEnv.subscriptionId);
    }
}
