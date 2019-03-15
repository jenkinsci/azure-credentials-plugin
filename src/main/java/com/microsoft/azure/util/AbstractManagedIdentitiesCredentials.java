package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.azure.AzureEnvironment;
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
        return azureEnvironment.endpoints();
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
        return azureEnvironment.managementEndpoint();
    }

    public String getActiveDirectoryEndpoint() {
        return azureEnvironment.activeDirectoryEndpoint();
    }

    public String getResourceManagerEndpoint() {
        return azureEnvironment.resourceManagerEndpoint();
    }

    public String getGraphEndpoint() {
        return azureEnvironment.graphEndpoint();
    }


    public AbstractManagedIdentitiesCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }
}
