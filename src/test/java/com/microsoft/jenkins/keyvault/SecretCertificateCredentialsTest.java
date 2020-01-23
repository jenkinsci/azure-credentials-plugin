/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.azure.keyvault.models.SecretBundle;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

public class SecretCertificateCredentialsTest {

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    private static class MockCertSecretGetter implements BaseSecretCredentials.SecretGetter {

        private final String cert;

        private MockCertSecretGetter(String cert) {
            this.cert = cert;
        }

        @Override
        public SecretBundle getKeyVaultSecret(String credentialId, String secretIdentifier) {
            Assert.assertEquals("spId", credentialId);
            Assert.assertEquals("secretId", secretIdentifier);

            final SecretBundle secretBundle = new SecretBundle();
            secretBundle.withValue(cert);
            secretBundle.withContentType("application/x-pkcs12");

            return secretBundle;
        }

    }

    @Test
    public void getKeyStore() throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final SecretCertificateCredentials c = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM,
                "id",
                "desc",
                "spId",
                "secretId",
                Secret.fromString("123456")
        );
        final String cert= IOUtils.toString(getClass().getResourceAsStream("cert.pfx.b64"), "UTF-8");
        c.setSecretGetter(new MockCertSecretGetter(cert));

        final KeyStore keyStore = c.getKeyStore();
        Assert.assertTrue(keyStore.containsAlias("msft"));
        Assert.assertEquals(1, keyStore.size());
        final Key key = keyStore.getKey("msft", "123456".toCharArray());
        Assert.assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    public void descriptorVerifyConfiguration() {
        final SecretCertificateCredentials.DescriptorImpl descriptor = new SecretCertificateCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration("", "", Secret.fromString(""));
        Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

}
