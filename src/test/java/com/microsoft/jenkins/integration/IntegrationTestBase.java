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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.rules.Timeout;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

public abstract class IntegrationTestBase {

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    @Rule
    public Timeout globalTimeout = new Timeout(20, TimeUnit.MINUTES);

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
            this.resourceGroup= TestEnvironment.loadFromEnv(ENV_PREFIX + "RESOURCE_GROUP_PREFIX",
                    "azure-credentials-tst-" + TestEnvironment.GenerateRandomString(16));
            this.region = Region.fromName(TestEnvironment.loadFromEnv(
                    ENV_PREFIX + "REGION", Region.ASIA_SOUTHEAST.name()));
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

    @BeforeClass
    public static void setUpClass() {
        if (testEnv == null) {
            testEnv = new TestEnvironment();
        }
    }

    @AfterClass
    public static void tearDownClass() {
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

        return AzureResourceManager
                .authenticate(credential, profile)
                .withSubscription(testEnv.subscriptionId);
    }

}
