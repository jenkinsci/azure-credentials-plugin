/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

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
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

public class SecretStringCredentialsTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void getSecret() {
        final BaseSecretCredentials.SecretGetter secretGetter = (credentialId, secretIdentifier) -> {
            Assert.assertEquals("spId", credentialId);
            Assert.assertEquals("secretId", secretIdentifier);

            return new KeyVaultSecret("name", "Secret");
        };
        final SecretStringCredentials c =
                new SecretStringCredentials(CredentialsScope.SYSTEM, "id", "desc", "spId", "secretId");
        c.setSecretGetter(secretGetter);

        final Secret secret = c.getSecret();
        Assert.assertEquals("Secret", secret.getPlainText());
    }

    @Test
    public void descriptorVerifyConfigurationAsAdmin() {
        // No security realm, anonymous has Overall/Administer
        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration(null, "", "");
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

        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            FormValidation result = descriptor.doVerifyConfiguration(folder, "", "");
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

        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            Assert.assertThrows(AccessDeniedException3.class, () -> descriptor.doVerifyConfiguration(folder, "", ""));
        }
    }
}
