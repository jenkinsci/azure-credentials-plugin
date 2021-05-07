package com.microsoft.azure.util;

import com.azure.core.management.AzureEnvironment;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;

public abstract class AzureBaseCredentials extends BaseStandardCredentials {
    public AzureBaseCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    public abstract String getAzureEnvironmentName();

    public abstract String getManagementEndpoint();

    public abstract String getActiveDirectoryEndpoint();

    public abstract String getResourceManagerEndpoint();

    public abstract String getGraphEndpoint();

    public abstract String getSubscriptionId();

    public abstract AzureEnvironment getAzureEnvironment();
}
