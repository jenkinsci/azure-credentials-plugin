package com.microsoft.azure.util;

import com.azure.core.http.rest.PagedIterable;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ManagedIdentityCredential;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.resources.models.Subscription;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.apache.commons.lang.StringUtils;
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

            AzureProfile profile = new AzureProfile(AzureEnvUtil.resolveAzureEnv(getAzureEnvName()));
            ManagedIdentityCredential credential = new ManagedIdentityCredentialBuilder().build();
            AzureResourceManager azure = AzureResourceManager
                    .configure()
                    .withHttpClient(AzureCredentials.getHttpClient())
                    .authenticate(credential, profile)
                    .withSubscription(credentialSubscriptionId);

            PagedIterable<Subscription> subscriptions = azure.subscriptions().list();
            if (subscriptionId != null) {
                for (Subscription subscription : subscriptions) {
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
