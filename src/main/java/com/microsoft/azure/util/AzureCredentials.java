/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for
 * license information.
 */
package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.resources.Subscription;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class AzureCredentials extends BaseStandardCredentials {
    static final LinkedHashMap<String, Pair<String, AzureEnvironment>> ENVIRONMENT_MAP = new LinkedHashMap<>();

    static {
        ENVIRONMENT_MAP.put("AZURE",
                Pair.of("Azure", AzureEnvironment.AZURE));
        ENVIRONMENT_MAP.put("AZURE_CHINA",
                Pair.of("Azure China", AzureEnvironment.AZURE_CHINA));
        ENVIRONMENT_MAP.put("AZURE_GERMANY",
                Pair.of("Azure Germany", AzureEnvironment.AZURE_GERMANY));
        ENVIRONMENT_MAP.put("AZURE_US_GOVERNMENT",
                Pair.of("Azure US Government", AzureEnvironment.AZURE_US_GOVERNMENT));
    }

    static final String DEFAULT_ENVIRONMENT = "AZURE";

    public static class ValidationException extends Exception {

        public ValidationException(final String message) {
            super(message);
        }
    }

    public static class ServicePrincipal implements java.io.Serializable {

        // version marker for ease of possible future data migration
        private final String azureSDKVersion = "1.1.0";

        private final Secret subscriptionId;
        private final Secret clientId;
        private final Secret clientSecret;
        private final Secret tenant;
        private final String environmentStr;
        private final String managementEndpointUrl;
        private final String activeDirectoryEndpointUrl;
        private final String resourceManagerEndpointUrl;
        private final String graphEndpointUrl;

        private transient AzureEnvironment azureEnvironment;

        public final String getSubscriptionId() {
            if (subscriptionId == null) {
                return "";
            } else {
                return subscriptionId.getPlainText();
            }
        }

        public final String getClientId() {
            if (clientId == null) {
                return "";
            } else {
                return clientId.getPlainText();
            }
        }

        public final String getClientSecret() {
            if (clientSecret == null) {
                return "";
            } else {
                return clientSecret.getPlainText();
            }
        }

        public final String getTenant() {
            if (tenant == null) {
                return "";
            } else {
                return tenant.getPlainText();
            }
        }

        public final String getEnvironmentStr() {
            if (environmentStr == null) {
                return "";
            } else {
                return environmentStr;
            }
        }

        public final String getManagementEndpointUrl() {
            if (managementEndpointUrl == null) {
                return "";
            } else {
                return managementEndpointUrl;
            }
        }

        /**
         * Previously used to provide a parameter to construct the AzureEnvironment.
         *
         * @deprecated Call {@link #getAzureEnvironment()}.
         * @return the management endpoint URL
         */
        public final String getServiceManagementURL() {
            if (StringUtils.isNotBlank(managementEndpointUrl)) {
                return managementEndpointUrl;
            }
            return ensureTrailingSlash(getAzureEnvironment().managementEndpoint());
        }

        public final String getActiveDirectoryEndpointUrl() {
            if (activeDirectoryEndpointUrl == null) {
                return "";
            } else {
                return activeDirectoryEndpointUrl;
            }
        }

        /**
         * Previously used to provide a parameter to construct the AzureEnvironment.
         *
         * @deprecated Call {@link #getAzureEnvironment()}.
         * @return the Active Directory endpoint URL
         */
        public final String getAuthenticationEndpoint() {
            if (StringUtils.isNotBlank(activeDirectoryEndpointUrl)) {
                return activeDirectoryEndpointUrl;
            }
            return ensureTrailingSlash(getAzureEnvironment().activeDirectoryEndpoint());
        }

        public final String getResourceManagerEndpointUrl() {
            if (resourceManagerEndpointUrl == null) {
                return "";
            } else {
                return resourceManagerEndpointUrl;
            }
        }

        /**
         * Previously used to provide a parameter to construct the AzureEnvironment.
         *
         * @deprecated Call {@link #getAzureEnvironment()}.
         * @return the Resource Manager endpoint URL
         */
        public final String getResourceManagerEndpoint() {
            if (StringUtils.isNotBlank(resourceManagerEndpointUrl)) {
                return resourceManagerEndpointUrl;
            }
            return ensureTrailingSlash(getAzureEnvironment().resourceManagerEndpoint());
        }

        public final String getGraphEndpointUrl() {
            if (graphEndpointUrl == null) {
                return "";
            } else {
                return graphEndpointUrl;
            }
        }

        /**
         * Previously used to provide a parameter to construct the AzureEnvironment.
         *
         * @deprecated Call {@link #getAzureEnvironment()}.
         * @return the graph endpoint URL
         */
        public final String getGraphEndpoint() {
            if (StringUtils.isNotBlank(graphEndpointUrl)) {
                return graphEndpointUrl;
            }
            return ensureTrailingSlash(getAzureEnvironment().graphEndpoint());
        }

        public final AzureEnvironment getAzureEnvironment() {
            if (azureEnvironment != null) {
                return azureEnvironment;
            }

            Pair<String, AzureEnvironment> pair = ENVIRONMENT_MAP.get(environmentStr);
            AzureEnvironment base;
            if (pair == null) {
                base = AzureEnvironment.AZURE;
            } else {
                base = pair.getRight();
            }

            HashMap<String, String> endpoints = new HashMap<>(base.endpoints());
            boolean overridden = false;
            if (StringUtils.isNotBlank(managementEndpointUrl)) {
                endpoints.put("managementEndpointUrl", managementEndpointUrl);
                overridden = true;
            }
            if (StringUtils.isNotBlank(activeDirectoryEndpointUrl)) {
                endpoints.put("activeDirectoryEndpointUrl", activeDirectoryEndpointUrl);
                overridden = true;
            }
            if (StringUtils.isNotBlank(resourceManagerEndpointUrl)) {
                endpoints.put("resourceManagerEndpointUrl", resourceManagerEndpointUrl);
                overridden = true;
            }
            if (StringUtils.isNotBlank(graphEndpointUrl)) {
                endpoints.put("activeDirectoryGraphResourceId", graphEndpointUrl);
                overridden = true;
            }
            if (overridden) {
                azureEnvironment = new AzureEnvironment(endpoints);
            } else {
                azureEnvironment = base;
            }
            return azureEnvironment;
        }

        public ServicePrincipal(
                final String subscriptionId,
                final String clientId,
                final String clientSecret,
                final String tenant,
                final String environmentStr,
                final String managementEndpointUrl,
                final String activeDirectoryEndpointUrl,
                final String resourceManagerEndpointUrl,
                final String graphEndpointUrl) {
            this.subscriptionId = Secret.fromString(StringUtils.trimToEmpty(subscriptionId));
            this.clientId = Secret.fromString(StringUtils.trimToEmpty(clientId));
            this.clientSecret = Secret.fromString(StringUtils.trimToEmpty(clientSecret));
            this.tenant = Secret.fromString(StringUtils.trimToEmpty(tenant));
            this.environmentStr = StringUtils.trimToEmpty(environmentStr);
            this.managementEndpointUrl = StringUtils.trimToEmpty(managementEndpointUrl);
            this.activeDirectoryEndpointUrl = StringUtils.trimToEmpty(activeDirectoryEndpointUrl);
            this.resourceManagerEndpointUrl = StringUtils.trimToEmpty(resourceManagerEndpointUrl);
            this.graphEndpointUrl = StringUtils.trimToEmpty(graphEndpointUrl);

            this.azureEnvironment = getAzureEnvironment();
        }

        public ServicePrincipal() {
            this.subscriptionId = Secret.fromString("");
            this.clientId = Secret.fromString("");
            this.clientSecret = Secret.fromString("");
            this.tenant = Secret.fromString("");
            this.environmentStr = DEFAULT_ENVIRONMENT;
            this.managementEndpointUrl = "";
            this.activeDirectoryEndpointUrl = "";
            this.resourceManagerEndpointUrl = "";
            this.graphEndpointUrl = "";
        }

        public final boolean isBlank() {
            return StringUtils.isBlank(subscriptionId.getPlainText())
                    || StringUtils.isBlank(clientId.getPlainText())
                    || StringUtils.isBlank(tenant.getPlainText())
                    || StringUtils.isBlank(clientSecret.getPlainText())
                    || StringUtils.isBlank(environmentStr);
        }

        public final boolean validate() throws ValidationException {
            if (StringUtils.isBlank(subscriptionId.getPlainText())) {
                throw new ValidationException(Messages.Azure_SubscriptionID_Missing());
            }
            if (StringUtils.isBlank(clientId.getPlainText())) {
                throw new ValidationException(Messages.Azure_ClientID_Missing());
            }
            if (StringUtils.isBlank(clientSecret.getPlainText())) {
                throw new ValidationException(Messages.Azure_ClientSecret_Missing());
            }
            if (StringUtils.isBlank(tenant.getPlainText())) {
                throw new ValidationException(Messages.Azure_Tenant_Missing());
            }
            if (!ENVIRONMENT_MAP.containsKey(environmentStr)) {
                throw new ValidationException(Messages.Azure_Invalid_Azure_Environment());
            }

            try {
                final String credentialSubscriptionId = getSubscriptionId();
                Azure.Authenticated auth = Azure.authenticate(
                        new ApplicationTokenCredentials(
                                getClientId(),
                                getTenant(),
                                getClientSecret(),
                                getAzureEnvironment())
                );
                for (Subscription subscription : auth.subscriptions().list()) {
                    if (subscription.subscriptionId().equalsIgnoreCase(credentialSubscriptionId)) {
                        return true;
                    }
                }
            } catch (Exception e) {
                throw new ValidationException(Messages.Azure_CantValidate());
            }
            throw new ValidationException(Messages.Azure_Invalid_SubscriptionId());
        }

        private static final int TOKEN_ENDPOINT_URL_ENDPOINT_POSTION = 3;

        public static String getTenantFromTokenEndpoint(final String oauth2TokenEndpoint) {
            if (!oauth2TokenEndpoint.matches(
                    "https{0,1}://[a-zA-Z0-9\\.]*/[a-z0-9\\-]*/?.*$")) {
                return "";
            } else {
                final String[] parts = oauth2TokenEndpoint.split("/");
                if (parts.length < TOKEN_ENDPOINT_URL_ENDPOINT_POSTION + 1) {
                    return "";
                } else {
                    return parts[TOKEN_ENDPOINT_URL_ENDPOINT_POSTION];
                }
            }
        }

        /**
         * Add forward slash to the tail of the URL, if not exist.
         *
         * For backward compatibility. If we do not have trailing slash, we may encounter error on legacy Azure REST
         * API.
         *
         * Sample error:
         * <p>
         *   The access token has been obtained from wrong audience or resource 'https://management.core.windows.net'.
         *   It should exactly match (including forward slash) with one of the allowed audiences
         *   'https://management.core.windows.net/','https://management.azure.com/'.
         * </p>
         */
        private static String ensureTrailingSlash(String url) {
            if (StringUtils.isEmpty(url)) {
                return "/";
            }
            if (url.charAt(url.length() - 1) != '/') {
                return url + '/';
            }
            return url;
        }
    }

    private final ServicePrincipal data;

    @DataBoundConstructor
    public AzureCredentials(
            final CredentialsScope scope,
            final String id,
            final String description,
            final String subscriptionId,
            final String clientId,
            final String clientSecret,
            final String tenant,
            final String environmentStr,
            final String managementEndpointUrl,
            final String activeDirectoryEndpointUrl,
            final String resourceManagerEndpointUrl,
            final String graphEndpointUrl) {
        super(scope, id, description);
        data = new ServicePrincipal(
                subscriptionId,
                clientId,
                clientSecret,
                tenant,
                environmentStr,
                managementEndpointUrl,
                activeDirectoryEndpointUrl,
                resourceManagerEndpointUrl,
                graphEndpointUrl);
    }

    public static AzureCredentials.ServicePrincipal getServicePrincipal(
            final String credentialsId) {
        AzureCredentials creds = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialsId));
        if (creds == null) {
            return new AzureCredentials.ServicePrincipal();
        }
        return creds.data;
    }

    public final String getSubscriptionId() {
        return data.subscriptionId.getPlainText();
    }

    public final String getClientId() {
        return data.clientId.getPlainText();
    }

    public final String getClientSecret() {
        return data.clientSecret.getPlainText();
    }

    public final String getTenant() {
        return data.tenant.getPlainText();
    }

    public final String getEnvironmentStr() {
        return data.environmentStr;
    }

    public final String getManagementEndpointUrl() {
        return data.managementEndpointUrl;
    }

    public final String getActiveDirectoryEndpointUrl() {
        return data.activeDirectoryEndpointUrl;
    }

    public final String getResourceManagerEndpointUrl() {
        return data.resourceManagerEndpointUrl;
    }

    public final String getGraphEndpointUrl() {
        return data.graphEndpointUrl;
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Initializer(before = InitMilestone.PLUGINS_STARTED)
        public static void upgradeAzureCredentialsConfig() {
            try {
                CredentialsMigration.upgradeAzureCredentialsConfig();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public final String getDisplayName() {
            return "Microsoft Azure Service Principal";
        }

        public final FormValidation doVerifyConfiguration(
                @QueryParameter final String subscriptionId,
                @QueryParameter final String clientId,
                @QueryParameter final String clientSecret,
                @QueryParameter final String tenant,
                @QueryParameter final String environmentStr,
                @QueryParameter final String managementEndpointUrl,
                @QueryParameter final String activeDirectoryEndpointUrl,
                @QueryParameter final String resourceManagerEndpointUrl,
                @QueryParameter final String graphEndpointUrl) {

            if (!ENVIRONMENT_MAP.containsKey(environmentStr)) {
                return FormValidation.error("Invalid Azure Environment " + environmentStr);
            }

            AzureCredentials.ServicePrincipal servicePrincipal
                    = new AzureCredentials.ServicePrincipal(
                    subscriptionId,
                    clientId,
                    clientSecret,
                    tenant,
                    environmentStr,
                    managementEndpointUrl,
                    activeDirectoryEndpointUrl,
                    resourceManagerEndpointUrl,
                    graphEndpointUrl);
            try {
                servicePrincipal.validate();
            } catch (ValidationException e) {
                return FormValidation.error(e.getMessage());
            }

            return FormValidation.ok(Messages.Azure_Config_Success());
        }

        public final ListBoxModel doFillEnvironmentStrItems() {
            ListBoxModel model = new ListBoxModel();
            for (Map.Entry<String, Pair<String, AzureEnvironment>> entry : ENVIRONMENT_MAP.entrySet()) {
                model.add(entry.getValue().getLeft(), entry.getKey());
            }
            return model;
        }
    }
}
