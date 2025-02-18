/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessDeniedException3;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import jenkins.model.Jenkins;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class SecretCertificateCredentialsTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private static class MockCertSecretGetter implements BaseSecretCredentials.SecretGetter {

        private final String cert;

        private MockCertSecretGetter(String cert) {
            this.cert = cert;
        }

        @Override
        public KeyVaultSecret getKeyVaultSecret(String credentialId, String secretIdentifier) {
            Assert.assertEquals("spId", credentialId);
            Assert.assertEquals("secretId", secretIdentifier);

            final KeyVaultSecret secretBundle = new KeyVaultSecret("name", cert);
            secretBundle.setProperties(new SecretProperties().setContentType("application/x-pkcs12"));

            return secretBundle;
        }
    }

    @Test
    public void getKeyStore()
            throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final SecretCertificateCredentials c = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "id", "desc", "spId", "secretId", Secret.fromString("123456"));
        final String cert = IOUtils.toString(getClass().getResourceAsStream("cert.pfx.b64"), StandardCharsets.UTF_8);
        c.setSecretGetter(new MockCertSecretGetter(cert));

        final KeyStore keyStore = c.getKeyStore();
        Assert.assertTrue(keyStore.containsAlias("msft"));
        Assert.assertEquals(1, keyStore.size());
        final Key key = keyStore.getKey("msft", "123456".toCharArray());
        Assert.assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    public void descriptorVerifyConfigurationAsAdmin() {
        // No security realm, anonymous has Overall/Administer
        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration(null, "", "", Secret.fromString(""));
        Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    public void descriptorVerifyConfigurationWithAncestorAsAuthorizedUser() throws Exception {
        Folder folder = j.jenkins.createProject(Folder.class, "folder");
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        MockAuthorizationStrategy authorizationStrategy = new MockAuthorizationStrategy();
        authorizationStrategy.grant(Jenkins.READ).everywhere().to("user");
        authorizationStrategy.grant(Item.CONFIGURE).onFolders(folder).to("user");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            FormValidation result = descriptor.doVerifyConfiguration(folder, "", "", Secret.fromString(""));
            // we aren't looking up an actual secret so this fails with missing protocol
            // TODO mock secrets retrieval so we can test the happy case here properly
            Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);
        }
    }

    @Test
    public void descriptorVerifyConfigurationWithAncestorAsUnauthorizedUser() throws Exception {
        Folder folder = j.jenkins.createProject(Folder.class, "folder");
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        MockAuthorizationStrategy authorizationStrategy = new MockAuthorizationStrategy();
        authorizationStrategy.grant(Jenkins.READ).everywhere().to("user");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            Assert.assertThrows(
                    AccessDeniedException3.class,
                    () -> descriptor.doVerifyConfiguration(folder, "", "", Secret.fromString("")));
        }
    }
}
