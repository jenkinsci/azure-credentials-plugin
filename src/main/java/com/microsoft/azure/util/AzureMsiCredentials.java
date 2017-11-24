package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.azure.AzureEnvironment;
import hudson.Extension;
import hudson.util.ListBoxModel;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Map;

public class AzureMsiCredentials extends BaseStandardCredentials {

    public static final int DEFAULT_MSI_PORT = 50342;
    private static final long serialVersionUID = 6743945878507124459L;

    private final int msiPort;
    private String azureEnvName;
    private transient AzureEnvironment azureEnvironment;

    @DataBoundConstructor
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort,
                               String azureEnvName) {
        super(scope, id, description);
        this.msiPort = msiPort;
        this.azureEnvName = azureEnvName;

        resolveAzureEnv();
    }

    private void resolveAzureEnv() {
        if (AzureCredentials.Constants.ENV_AZURE.equalsIgnoreCase(azureEnvName)) {
            azureEnvironment = AzureEnvironment.AZURE;
        } else if (AzureCredentials.Constants.ENV_AZURE_CHINA.equalsIgnoreCase(azureEnvName)) {
            azureEnvironment = AzureEnvironment.AZURE_CHINA;
        } else if (AzureCredentials.Constants.ENV_AZURE_GERMANY.equalsIgnoreCase(azureEnvName)) {
            azureEnvironment = AzureEnvironment.AZURE_GERMANY;
        } else if (AzureCredentials.Constants.ENV_AZURE_US_GOVERNMENT.equalsIgnoreCase(azureEnvName)) {
            azureEnvironment = AzureEnvironment.AZURE_US_GOVERNMENT;
        } else {
            azureEnvironment = AzureEnvironment.AZURE;
        }
    }

    private Object readResolve() {
        if (StringUtils.isEmpty(azureEnvName)) {
            this.azureEnvName = AzureCredentials.Constants.ENV_AZURE;
        }
        resolveAzureEnv();
        return this;
    }

    public int getMsiPort() {
        return msiPort;
    }

    private AzureEnvironment getAzureEnvironment() {
        return azureEnvironment;
    }

    public String getAzureEnvName() {
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

    public Map<String, String> getEndpoints() {
        return azureEnvironment.endpoints();
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Microsoft Azure Managed Service Identity";
        }

        public int getDefaultMsiPort() {
            return DEFAULT_MSI_PORT;
        }

        public ListBoxModel doFillAzureEnvNameItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(AzureCredentials.Constants.ENV_AZURE);
            model.add(AzureCredentials.Constants.ENV_AZURE_CHINA);
            model.add(AzureCredentials.Constants.ENV_AZURE_GERMANY);
            model.add(AzureCredentials.Constants.ENV_AZURE_US_GOVERNMENT);
            return model;
        }
    }
}
