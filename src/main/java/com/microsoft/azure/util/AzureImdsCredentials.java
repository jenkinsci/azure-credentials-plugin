package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.azure.PagedList;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.resources.Subscription;
import com.microsoft.jenkins.azurecommons.core.credentials.ImdsTokenCredentials;
import com.microsoft.jenkins.azurecommons.core.credentials.TokenCredentialData;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.apache.commons.lang3.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class AzureImdsCredentials extends AbstractManagedIdentitiesCredentials {

    private String subscriptionId;

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

    @Override
    public TokenCredentialData createToken() {
        TokenCredentialData token = super.createToken();
        token.setType(TokenCredentialData.TYPE_IMDS);
        token.setSubscriptionId(getSubscriptionId());
        return token;
    }

    public String getSubscriptionId() {
        return subscriptionId;
    }

    @DataBoundSetter
    public void setSubscriptionId(String subscriptionId) {
        this.subscriptionId = Util.fixEmpty(subscriptionId);
    }

    public boolean validate() throws AzureCredentials.ValidationException {
        try {
            final String credentialSubscriptionId = getSubscriptionId();

            Azure.Authenticated auth = Azure.authenticate(
                        new ImdsTokenCredentials(AzureEnvUtil.resolveAzureEnv(getAzureEnvName())));
            PagedList<Subscription> list = auth.subscriptions().list();
            if (subscriptionId != null) {
                for (Subscription subscription : list) {
                    if (subscription.subscriptionId().equalsIgnoreCase(credentialSubscriptionId)) {
                        return true;
                    }
                }
            } else {
                return true;
            }
        } catch (Exception e) {
            throw new AzureCredentials.ValidationException(Messages.Azure_CantValidate() + ": " + e.getMessage());
        }
        throw new AzureCredentials.ValidationException(Messages.Azure_Invalid_SubscriptionId());
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

        public FormValidation doVerifyConfiguration(
                @QueryParameter String subscriptionId,
                @QueryParameter String azureEnvironmentName) {

            AzureImdsCredentials imdsCredentials = new AzureImdsCredentials(null, null, null, azureEnvironmentName);
            if (StringUtils.isNotBlank(subscriptionId)) {
                imdsCredentials.setSubscriptionId(subscriptionId);
            }
            try {
                imdsCredentials.validate();
            } catch (AzureCredentials.ValidationException e) {
                return FormValidation.error(e.getMessage());
            }

            return FormValidation.ok(Messages.Azure_MI_Config_Success());
        }

    }
}
