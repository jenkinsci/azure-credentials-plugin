/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.jenkins.keyvault.SecretStringCredentials;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ITSecretStringCredentials extends KeyVaultIntegrationTestBase {

    @Test
    void getSecret() {
        final KeyVaultSecret secretBundle = createSecret("secret-string", "I'm secret");
        final String secretIdentifier = secretBundle.getId();

        // Verify configuration
        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();
        final FormValidation result =
                descriptor.doVerifyConfiguration(null, jenkinsAzureCredentialsId, secretIdentifier);
        assertEquals(FormValidation.Kind.OK, result.kind);

        // Get secret
        final SecretStringCredentials credentials = new SecretStringCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier);
        final Secret secret = credentials.getSecret();
        assertEquals("I'm secret", secret.getPlainText());
    }

    @Test
    void getSecretNotFound() {
        final String secretIdentifier = vaultUri + "/secrets/not-found/869660651aa3436994bd7290704c9394";

        // Verify configuration
        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();
        final FormValidation result =
                descriptor.doVerifyConfiguration(null, jenkinsAzureCredentialsId, secretIdentifier);
        assertEquals(FormValidation.Kind.ERROR, result.kind);

        // Get secret
        final SecretStringCredentials credentials = new SecretStringCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier);
        assertThrows(IOException.class, credentials::getSecret);
    }
}
