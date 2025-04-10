/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class SecretCertificateCredentialsTest {

    private static class MockCertSecretGetter implements BaseSecretCredentials.SecretGetter {

        private final String cert;

        private MockCertSecretGetter(String cert) {
            this.cert = cert;
        }

        @Override
        public KeyVaultSecret getKeyVaultSecret(String credentialId, String secretIdentifier) {
            assertEquals("spId", credentialId);
            assertEquals("secretId", secretIdentifier);

            final KeyVaultSecret secretBundle = new KeyVaultSecret("name", cert);
            secretBundle.setProperties(new SecretProperties().setContentType("application/x-pkcs12"));

            return secretBundle;
        }
    }

    @Test
    void getKeyStore(JenkinsRule j)
            throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final SecretCertificateCredentials c = new SecretCertificateCredentials(
                CredentialsScope.SYSTEM, "id", "desc", "spId", "secretId", Secret.fromString("123456"));
        final String cert = IOUtils.toString(getClass().getResourceAsStream("cert.pfx.b64"), StandardCharsets.UTF_8);
        c.setSecretGetter(new MockCertSecretGetter(cert));

        final KeyStore keyStore = c.getKeyStore();
        assertTrue(keyStore.containsAlias("msft"));
        assertEquals(1, keyStore.size());
        final Key key = keyStore.getKey("msft", "123456".toCharArray());
        assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    void descriptorVerifyConfigurationAsAdmin(JenkinsRule j) {
        // No security realm, anonymous has Overall/Administer
        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration(null, "", "", Secret.fromString(""));
        assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

    @Test
    void descriptorVerifyConfigurationWithAncestorAsAuthorizedUser(JenkinsRule j) throws Exception {
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
            assertEquals(FormValidation.Kind.ERROR, result.kind);
        }
    }

    @Test
    void descriptorVerifyConfigurationWithAncestorAsUnauthorizedUser(JenkinsRule j) throws Exception {
        Folder folder = j.jenkins.createProject(Folder.class, "folder");
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        MockAuthorizationStrategy authorizationStrategy = new MockAuthorizationStrategy();
        authorizationStrategy.grant(Jenkins.READ).everywhere().to("user");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        final SecretCertificateCredentials.DescriptorImpl descriptor =
                new SecretCertificateCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            assertThrows(
                    AccessDeniedException3.class,
                    () -> descriptor.doVerifyConfiguration(folder, "", "", Secret.fromString("")));
        }
    }
}
