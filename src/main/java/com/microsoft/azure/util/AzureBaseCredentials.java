package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.jenkins.azurecommons.core.credentials.TokenCredentialData;

public abstract class AzureBaseCredentials extends BaseStandardCredentials {
    public AzureBaseCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    public abstract String getAzureEnvironmentName();

    public abstract String getManagementEndpoint();

    public abstract String getActiveDirectoryEndpoint();

    public abstract String getResourceManagerEndpoint();

    public abstract String getGraphEndpoint();

    public TokenCredentialData createToken() {
        TokenCredentialData token = new TokenCredentialData();
        token.setAzureEnvironmentName(getAzureEnvironmentName());
        token.setResourceManagerEndpoint(getResourceManagerEndpoint());
        token.setManagementEndpoint(getManagementEndpoint());
        token.setActiveDirectoryEndpoint(getActiveDirectoryEndpoint());
        token.setGraphEndpoint(getGraphEndpoint());
        return token;
    }

    public byte[] serializeToTokenData() {
        return TokenCredentialData.serialize(createToken());
    }
}
