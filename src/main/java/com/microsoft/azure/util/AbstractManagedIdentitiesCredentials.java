package com.microsoft.azure.util;

import com.azure.core.management.AzureEnvironment;
import com.cloudbees.plugins.credentials.CredentialsScope;
import org.apache.commons.lang.StringUtils;

import java.util.Map;

public abstract class AbstractManagedIdentitiesCredentials extends AzureBaseCredentials {
    private String azureEnvName;
    private transient AzureEnvironment azureEnvironment;

    protected Object readResolve() {
        if (StringUtils.isEmpty(azureEnvName)) {
            this.azureEnvName = AzureEnvUtil.Constants.ENV_AZURE;
        }
        azureEnvironment = AzureEnvUtil.resolveAzureEnv(azureEnvName);
        return this;
    }

    public Map<String, String> getEndpoints() {
        return azureEnvironment.getEndpoints();
    }

    private AzureEnvironment getAzureEnvironment() {
        return azureEnvironment;
    }

    public String getAzureEnvName() {
        return azureEnvName;
    }

    protected void setAzureEnvName(String azureEnvName) {
        this.azureEnvName = azureEnvName;
    }

    protected void setAzureEnvironment(AzureEnvironment azureEnvironment) {
        this.azureEnvironment = azureEnvironment;
    }

    @Override
    public String getAzureEnvironmentName() {
        return azureEnvName;
    }

    public String getManagementEndpoint() {
        return azureEnvironment.getManagementEndpoint();
    }

    public String getActiveDirectoryEndpoint() {
        return azureEnvironment.getActiveDirectoryEndpoint();
    }

    public String getResourceManagerEndpoint() {
        return azureEnvironment.getResourceManagerEndpoint();
    }

    public String getGraphEndpoint() {
        return azureEnvironment.getGraphEndpoint();
    }


    public AbstractManagedIdentitiesCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }
}
