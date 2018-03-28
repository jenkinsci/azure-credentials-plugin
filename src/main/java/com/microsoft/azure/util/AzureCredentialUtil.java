package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import hudson.model.Item;
import hudson.security.ACL;
import jenkins.model.Jenkins;

import javax.annotation.Nullable;
import java.util.Collections;

public final class AzureCredentialUtil {
    private AzureCredentialUtil() {

    }

    public static AzureBaseCredentials getCredential(@Nullable Item owner, String credentialId) {
        return CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureBaseCredentials.class,
                        owner,
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
    }

    public static String getManagementEndpoint(@Nullable Item owner, String credentialId) {
        AzureBaseCredentials credential = getCredential(owner, credentialId);
        if (credential != null) {
            return credential.getManagementEndpoint();
        } else {
            return null;
        }
    }

    /**
     * @deprecated see {@link #getCredential(Item, String)}
     */
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

    /**
     * @deprecated see {@link #getCredential(Item, String)}
     */
    @Deprecated
    public static AzureBaseCredentials getCredential2(String credentialId) {
        return getCredential(null, credentialId);
    }

    /**
     * @deprecated see {@link #getManagementEndpoint(Item, String)}
     */
    @Deprecated
    public static String getManagementEndpoint(String credentialId) {
        return getManagementEndpoint(null, credentialId);
    }
}
