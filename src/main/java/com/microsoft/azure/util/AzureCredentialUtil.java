package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.security.ACL;
import jenkins.model.Jenkins;

import java.util.Collections;

public final class AzureCredentialUtil {
    private AzureCredentialUtil() {

    }

    @Deprecated
    public static BaseCredentials getCredential(String credentialId) {
        BaseCredentials credential = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureMsiCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
        if (credential != null) {
            return credential;
        } else {
            credential = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(
                            AzureCredentials.class,
                            Jenkins.getInstance(),
                            ACL.SYSTEM,
                            Collections.<DomainRequirement>emptyList()),
                    CredentialsMatchers.withId(credentialId));
            return credential;
        }
    }

    public static AzureBaseCredentials getCredential2(String credentialId) {
        return CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureBaseCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
    }

    public static String getManagementEndpoint(String credentialId) {
        AzureBaseCredentials credential = getCredential2(credentialId);
        if (credential != null) {
            return credential.getManagementEndpoint();
        } else {
            return null;
        }
    }
}
