/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.jenkins.keyvault.Messages;
import com.microsoft.jenkins.keyvault.SecretCertificateCredentials;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ITSecretCertificateCredentials extends KeyVaultIntegrationTestBase {

    @Test
    void getKeyStore() throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final String cert = IOUtils.toString(getClass().getResourceAsStream("../cert.pfx.b64"), StandardCharsets.UTF_8);
        final KeyVaultSecret secretBundle = createSecret("secret-cert", cert);
        final String secretIdentifier = secretBundle.getId();
        final Secret password = Secret.fromString("123456");

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result =
                descriptor.doVerifyConfiguration(null, jenkinsAzureCredentialsId, secretIdentifier, password);
        assertEquals(FormValidation.Kind.OK, result.kind);

        // Get key store
        final SecretCertificateCredentials credentials = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier, password);
        final KeyStore keyStore = credentials.getKeyStore();
        assertTrue(keyStore.containsAlias("msft"));
        assertEquals(1, keyStore.size());
        final Key key = keyStore.getKey("msft", password.getPlainText().toCharArray());
        assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    void getKeyStoreNotFound() {
        final String secretIdentifier = vaultUri + "/secrets/not-found/869660651aa3436994bd7290704c9394";

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result = descriptor.doVerifyConfiguration(
                null, jenkinsAzureCredentialsId, secretIdentifier, Secret.fromString(""));
        assertEquals(FormValidation.Kind.ERROR, result.kind);

        // Get key store
        final SecretCertificateCredentials credentials = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier, Secret.fromString(""));

        assertThrows(IOException.class, credentials::getKeyStore);
    }

    @Test
    void getKeyStoreNoPrivateKey() throws IOException {
        final String cert =
                IOUtils.toString(getClass().getResourceAsStream("../cert_no_private.pfx.b64"), StandardCharsets.UTF_8);
        final KeyVaultSecret secretBundle = createSecret("secret-cert-no-private", cert);
        final String secretIdentifier = secretBundle.getId();

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result = descriptor.doVerifyConfiguration(
                null, jenkinsAzureCredentialsId, secretIdentifier, Secret.fromString(""));
        assertEquals(FormValidation.Kind.ERROR, result.kind);
        assertEquals(Messages.Certificate_Credentials_Validation_No_Private_Key(), result.getMessage());
    }
}
