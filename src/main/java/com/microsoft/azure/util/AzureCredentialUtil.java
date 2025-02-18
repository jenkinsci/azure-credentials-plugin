package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.BaseCredentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.model.Item;
import hudson.security.ACL;
import java.util.Collections;
import jenkins.model.Jenkins;

public final class AzureCredentialUtil {
    private AzureCredentialUtil() {}

    public static AzureBaseCredentials getCredential(@Nullable Item owner, String credentialId) {
        return CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentialsInItem(
                        AzureBaseCredentials.class, owner, ACL.SYSTEM2, Collections.emptyList()),
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
                        AzureImdsCredentials.class, Jenkins.getInstance(), ACL.SYSTEM, Collections.emptyList()),
                CredentialsMatchers.withId(credentialId));
        if (credential == null) {
            credential = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(
                            AzureCredentials.class, Jenkins.getInstance(), ACL.SYSTEM, Collections.emptyList()),
                    CredentialsMatchers.withId(credentialId));
        }
        return credential;
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
