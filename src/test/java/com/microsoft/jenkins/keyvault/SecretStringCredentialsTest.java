/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessDeniedException3;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class SecretStringCredentialsTest {

    @Test
    void getSecret(JenkinsRule j) {
        final BaseSecretCredentials.SecretGetter secretGetter = (credentialId, secretIdentifier) -> {
            assertEquals("spId", credentialId);
            assertEquals("secretId", secretIdentifier);

            return new KeyVaultSecret("name", "Secret");
        };
        final SecretStringCredentials c =
                new SecretStringCredentials(CredentialsScope.SYSTEM, "id", "desc", "spId", "secretId");
        c.setSecretGetter(secretGetter);

        final Secret secret = c.getSecret();
        assertEquals("Secret", secret.getPlainText());
    }

    @Test
    void descriptorVerifyConfigurationAsAdmin(JenkinsRule j) {
        // No security realm, anonymous has Overall/Administer
        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration(null, "", "");
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

        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            FormValidation result = descriptor.doVerifyConfiguration(folder, "", "");
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

        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            assertThrows(AccessDeniedException3.class, () -> descriptor.doVerifyConfiguration(folder, "", ""));
        }
    }
}
