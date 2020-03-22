package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.DataBoundConstructor;

@Deprecated
public class AzureMsiCredentials extends AbstractManagedIdentitiesCredentials {
    public static final int DEFAULT_MSI_PORT = 50342;
    private static final long serialVersionUID = 1L;

    private final int msiPort;

    @Deprecated
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort) {
        this(scope, id, description, msiPort, AzureEnvUtil.Constants.ENV_AZURE);
    }

    @DataBoundConstructor
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort,
                               String azureEnvName) {
        super(scope, id, description);
        this.msiPort = msiPort;
        setAzureEnvName(azureEnvName);
        setAzureEnvironment(AzureEnvUtil.resolveAzureEnv(azureEnvName));
    }

    public int getMsiPort() {
        return msiPort;
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Microsoft Azure Managed Service Identity (deprecated)";
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
