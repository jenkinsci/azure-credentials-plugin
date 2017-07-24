/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault.integration;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.jenkins.keyvault.Messages;
import com.microsoft.jenkins.keyvault.SecretCertificateCredentials;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

public class ITSecretCertificateCredentials extends KeyVaultIntegrationTestBase {

    @Test
    public void getKeyStore() throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final String cert= IOUtils.toString(getClass().getResourceAsStream("../cert.pfx.b64"), "UTF-8");
        final SecretBundle secretBundle = createSecret("secret-cert", cert);
        final String secretIdentifier = secretBundle.secretIdentifier().toString();
        final Secret password = Secret.fromString("123456");

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor = new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result = descriptor.doVerifyConfiguration(
                jenkinsAzureCredentialsId, secretIdentifier, password);
        Assert.assertEquals(FormValidation.Kind.OK, result.kind);

        // Get key store
        final SecretCertificateCredentials credentials = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier, password
        );
        final KeyStore keyStore = credentials.getKeyStore();
        Assert.assertTrue(keyStore.containsAlias("msft"));
        Assert.assertEquals(1, keyStore.size());
        final Key key = keyStore.getKey("msft", password.getPlainText().toCharArray());
        Assert.assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    public void getKeyStoreNotFound() {
        final String secretIdentifier = vaultUri + "/secrets/not-found/869660651aa3436994bd7290704c9394";

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor = new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result = descriptor.doVerifyConfiguration(jenkinsAzureCredentialsId,
                secretIdentifier, Secret.fromString(""));
        Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);

        // Get key store
        final SecretCertificateCredentials credentials = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "", "", jenkinsAzureCredentialsId, secretIdentifier, Secret.fromString("")
        );
        try {
            final KeyStore keyStore = credentials.getKeyStore();
            Assert.fail("Should throw exception but not");
        } catch (Exception e) {
            // Expect exception
        }
    }

    @Test
    public void getKeyStoreNoPrivateKey() throws IOException {
        final String cert = IOUtils.toString(getClass().getResourceAsStream("../cert_no_private.pfx.b64"), "UTF-8");
        final SecretBundle secretBundle = createSecret("secret-cert-no-private", cert);
        final String secretIdentifier = secretBundle.secretIdentifier().toString();
        final Secret password = Secret.fromString("");

        // Verify configuration
        final SecretCertificateCredentials.DescriptorImpl descriptor = new SecretCertificateCredentials.DescriptorImpl();
        final FormValidation result = descriptor.doVerifyConfiguration(jenkinsAzureCredentialsId,
                secretIdentifier, Secret.fromString(""));
        Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);
        Assert.assertEquals(Messages.Certificate_Credentials_Validation_No_Private_Key(), result.getMessage());
    }
}
