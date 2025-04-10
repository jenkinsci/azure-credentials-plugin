package com.microsoft.azure.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.AccessDeniedException3;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AzureImdsCredentialsTest {

    @Test
    void descriptorVerifyConfigurationAsAdmin(JenkinsRule j) {
        // No security realm, anonymous has Overall/Administer
        final AzureImdsCredentials.DescriptorImpl descriptor = new AzureImdsCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration(null, "", "", "");
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

        final AzureImdsCredentials.DescriptorImpl descriptor = new AzureImdsCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            FormValidation result = descriptor.doVerifyConfiguration(folder, "", "", "");
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

        final AzureImdsCredentials.DescriptorImpl descriptor = new AzureImdsCredentials.DescriptorImpl();

        try (ACLContext ctx = ACL.as(User.getOrCreateByIdOrFullName("user"))) {
            assertThrows(AccessDeniedException3.class, () -> descriptor.doVerifyConfiguration(folder, "", "", ""));
        }
    }
}
