package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.DataBoundConstructor;

public class AzureImdsCredentials extends AbstractManagedIdentitiesCredentials {

    public AzureImdsCredentials(CredentialsScope scope, String id, String description) {
        super(scope, id, description);
    }

    @DataBoundConstructor
    public AzureImdsCredentials(CredentialsScope scope, String id, String description,
                                String azureEnvName) {
        super(scope, id, description);
        setAzureEnvName(azureEnvName);
        setAzureEnvironment(AzureEnvUtil.resolveAzureEnv(azureEnvName));
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Managed Identities for Azure Resources";
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
