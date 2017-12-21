package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.jenkins.azurecommons.core.credentials.TokenCredentialData;
import hudson.Extension;
import hudson.util.ListBoxModel;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Map;

public class AzureMsiCredentials extends AzureBaseCredentials {

    public static final int DEFAULT_MSI_PORT = 50342;
    private static final long serialVersionUID = 1L;

    private final int msiPort;
    private String azureEnvName;
    private transient AzureEnvironment azureEnvironment;

    @Deprecated
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort) {
        this(scope, id, description, msiPort, AzureEnvUtil.Constants.ENV_AZURE);
    }

    @DataBoundConstructor
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort,
                               String azureEnvName) {
        super(scope, id, description);
        this.msiPort = msiPort;
        this.azureEnvName = azureEnvName;
        azureEnvironment = AzureEnvUtil.resolveAzureEnv(azureEnvName);
    }

    private Object readResolve() {
        if (StringUtils.isEmpty(azureEnvName)) {
            this.azureEnvName = AzureEnvUtil.Constants.ENV_AZURE;
        }
        azureEnvironment = AzureEnvUtil.resolveAzureEnv(azureEnvName);
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

    @Override
    public TokenCredentialData createToken() {
        TokenCredentialData token = super.createToken();
        token.setType(TokenCredentialData.TYPE_MSI);
        token.setMsiPort(msiPort);
        return token;
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
            model.add(AzureEnvUtil.Constants.ENV_AZURE);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_CHINA);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_GERMANY);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_US_GOVERNMENT);
            return model;
        }
    }
}
