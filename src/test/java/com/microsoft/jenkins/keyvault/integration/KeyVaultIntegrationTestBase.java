/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault.integration;

import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.keyvault.models.Vault;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.microsoft.azure.util.AzureCredentials;
import com.microsoft.jenkins.integration.IntegrationTestBase;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import hudson.util.Secret;
import org.junit.Assert;
import org.junit.Before;

public abstract class KeyVaultIntegrationTestBase extends IntegrationTestBase {

    private static final Logger LOGGER = Logger.getLogger(KeyVaultIntegrationTestBase.class.getName());

    protected String vaultName;
    protected String vaultUri;
    protected final String jenkinsAzureCredentialsId = "tst-keyvault-sp";

    @Before
    public void setUp() throws InterruptedException {
        // Create Azure KeyVault
        final AzureResourceManager azureClient = IntegrationTestBase.getAzureClient();
        vaultName = "tst-vault-" + TestEnvironment.GenerateRandomString(5);
        final Vault vault = azureClient.vaults().define(vaultName)
                .withRegion(testEnv.region)
                .withNewResourceGroup(testEnv.resourceGroup)
                .defineAccessPolicy()
                .forServicePrincipal(testEnv.clientId)
                .allowSecretAllPermissions()
                .attach()
                .create();
        vaultUri = vault.vaultUri();

        waitForKeyVaultAvailable();

        // Create Jenkins Azure Credentials
        final AzureCredentials credentials = new AzureCredentials(
                CredentialsScope.SYSTEM,
                jenkinsAzureCredentialsId,
                "",
                testEnv.subscriptionId,
                testEnv.clientId,
                Secret.fromString(testEnv.clientSecret));
        credentials.setTenant(testEnv.tenantId);

        final CredentialsStore store = CredentialsProvider.lookupStores(j.jenkins).iterator().next();
        try {
            store.addCredentials(Domain.global(), credentials);
        } catch (IOException e) {
            Assert.fail(e.getMessage());
        }
    }

    /**
     * Wait until key vault available.
     * <p>
     * There may be some delay before key vault becomes available once created.
     *
     */
    private void waitForKeyVaultAvailable() throws InterruptedException {
        final int maxRetry = 360;
        for (int i = 0; i < maxRetry; i++) {
            try {
                createSecret(String.format("wait-for-key-vault-available-%d", i), "");
            } catch (Exception ex) {
                LOGGER.info(String.format("Key vault is not available due to %s. Will retry after 1 second.",
                        ex.getMessage()));
                Thread.sleep(TimeUnit.SECONDS.toMillis(1));
                continue;
            }
            return;
        }
        Assert.fail("Key vault still not available after timeout.");
    }

    protected KeyVaultSecret createSecret(final String name, final String value) {
        KeyVaultSecret keyVaultSecret = new KeyVaultSecret(name, value);

        ClientSecretCredential clientSecretCredential = new ClientSecretCredentialBuilder()
                .clientId(testEnv.clientId)
                .clientSecret(testEnv.clientSecret)
                .tenantId(testEnv.tenantId)
                .build();

        SecretClient secretClient = AzureCredentials.createKeyVaultClient(clientSecretCredential, vaultUri);
        return secretClient.setSecret(keyVaultSecret);
    }

}
