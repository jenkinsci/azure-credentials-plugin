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
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import java.util.Collections;

public class AzureCredentials extends BaseStandardCredentials {
    public static class ValidationException extends Exception {

        public ValidationException(final String message) {
            super(message);
        }
    }

    public static class Constants {

        public static final String DEFAULT_MANAGEMENT_URL
                = "https://management.core.windows.net/";
        public static final String DEFAULT_AUTHENTICATION_ENDPOINT
                = "https://login.microsoftonline.com/";
        public static final String DEFAULT_RESOURCE_MANAGER_ENDPOINT
                = "https://management.azure.com/";
        public static final String DEFAULT_GRAPH_ENDPOINT
                = "https://graph.windows.net/";
    }

    public static class ServicePrincipal implements java.io.Serializable {

        private final Secret subscriptionId;
        private final Secret clientId;
        private final Secret clientSecret;
        private final Secret oauth2TokenEndpoint; //keeping this for backwards compatibility
        private final String serviceManagementURL;
        private final Secret tenant;
        private final String authenticationEndpoint;
        private final String resourceManagerEndpoint;
        private final String graphEndpoint;

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
            if (tenant == null || StringUtils.isBlank(tenant.getPlainText())) {
                if (oauth2TokenEndpoint != null) {
                    return ServicePrincipal.getTenantFromTokenEndpoint(
                            oauth2TokenEndpoint.getPlainText());
                } else {
                    return ServicePrincipal.getTenantFromTokenEndpoint("");
                }
            } else {
                return tenant.getPlainText();
            }
        }

        public final String getServiceManagementURL() {
            if (serviceManagementURL == null) {
                return Constants.DEFAULT_MANAGEMENT_URL;
            } else {
                return serviceManagementURL;
            }
        }

        public final String getAuthenticationEndpoint() {
            if (authenticationEndpoint == null) {
                return Constants.DEFAULT_AUTHENTICATION_ENDPOINT;
            } else {
                return authenticationEndpoint;
            }
        }

        public final String getResourceManagerEndpoint() {
            if (resourceManagerEndpoint == null) {
                return Constants.DEFAULT_RESOURCE_MANAGER_ENDPOINT;
            } else {
                return resourceManagerEndpoint;
            }
        }

        public final String getGraphEndpoint() {
            if (graphEndpoint == null) {
                return Constants.DEFAULT_GRAPH_ENDPOINT;
            } else {
                return graphEndpoint;
            }
        }

        public ServicePrincipal(
                final String subscriptionId,
                final String clientId,
                final String clientSecret,
                final String oauth2TokenEndpoint,
                final String serviceManagementURL,
                final String authenticationEndpoint,
                final String resourceManagerEndpoint,
                final String graphEndpoint) {
            this.subscriptionId = Secret.fromString(subscriptionId);
            this.clientId = Secret.fromString(clientId);
            this.clientSecret = Secret.fromString(clientSecret);
            this.oauth2TokenEndpoint = Secret.fromString(oauth2TokenEndpoint);
            this.tenant = Secret.fromString(
                    ServicePrincipal.getTenantFromTokenEndpoint(oauth2TokenEndpoint));

            if (StringUtils.isBlank(serviceManagementURL)) {
                this.serviceManagementURL = Constants.DEFAULT_MANAGEMENT_URL;
            } else {
                this.serviceManagementURL = serviceManagementURL;
            }
            if (StringUtils.isBlank(authenticationEndpoint)) {
                this.authenticationEndpoint = Constants.DEFAULT_AUTHENTICATION_ENDPOINT;
            } else {
                this.authenticationEndpoint = authenticationEndpoint;
            }
            if (StringUtils.isBlank(resourceManagerEndpoint)) {
                this.resourceManagerEndpoint = Constants.DEFAULT_RESOURCE_MANAGER_ENDPOINT;
            } else {
                this.resourceManagerEndpoint = resourceManagerEndpoint;
            }
            if (StringUtils.isBlank(graphEndpoint)) {
                this.graphEndpoint = Constants.DEFAULT_GRAPH_ENDPOINT;
            } else {
                this.graphEndpoint = graphEndpoint;
            }
        }

        public ServicePrincipal() {
            this.subscriptionId = Secret.fromString("");
            this.clientId = Secret.fromString("");
            this.clientSecret = Secret.fromString("");
            this.oauth2TokenEndpoint = Secret.fromString("");
            this.tenant = Secret.fromString("");
            this.serviceManagementURL = Constants.DEFAULT_MANAGEMENT_URL;
            this.authenticationEndpoint = Constants.DEFAULT_AUTHENTICATION_ENDPOINT;
            this.resourceManagerEndpoint = Constants.DEFAULT_RESOURCE_MANAGER_ENDPOINT;
            this.graphEndpoint = Constants.DEFAULT_GRAPH_ENDPOINT;
        }

        public final boolean isBlank() {
            return StringUtils.isBlank(subscriptionId.getPlainText())
                    || StringUtils.isBlank(clientId.getPlainText())
                    || StringUtils.isBlank(oauth2TokenEndpoint.getPlainText())
                    || StringUtils.isBlank(clientSecret.getPlainText());
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
            if (StringUtils.isBlank(oauth2TokenEndpoint.getPlainText())) {
                throw new ValidationException(Messages.Azure_OAuthToken_Missing());
            }
            if (StringUtils.isBlank(getTenant())) {
                throw new ValidationException(Messages.Azure_OAuthToken_Malformed());
            }

            try {
                final String credentialSubscriptionId = getSubscriptionId();
                Azure.Authenticated auth = Azure.authenticate(
                        new ApplicationTokenCredentials(
                                getClientId(),
                                getTenant(),
                                getClientSecret(),
                                new AzureEnvironment(
                                        getAuthenticationEndpoint(),
                                        getServiceManagementURL(),
                                        getResourceManagerEndpoint(),
                                        getGraphEndpoint())
                        ));
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

        private static String getTenantFromTokenEndpoint(final String oauth2TokenEndpoint) {
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
            final String oauth2TokenEndpoint,
            final String serviceManagementURL,
            final String authenticationEndpoint,
            final String resourceManagerEndpoint,
            final String graphEndpoint) {
        super(scope, id, description);
        data = new ServicePrincipal(
                subscriptionId,
                clientId,
                clientSecret,
                oauth2TokenEndpoint,
                serviceManagementURL,
                authenticationEndpoint,
                resourceManagerEndpoint,
                graphEndpoint);
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
        return data.subscriptionId.getEncryptedValue();
    }

    public final String getClientId() {
        return data.clientId.getEncryptedValue();
    }

    public final String getClientSecret() {
        return data.clientSecret.getEncryptedValue();
    }

    public final String getOauth2TokenEndpoint() {
        return data.oauth2TokenEndpoint.getEncryptedValue();
    }

    public final String getServiceManagementURL() {
        return data.serviceManagementURL;
    }

    public final String getAuthenticationEndpoint() {
        return data.authenticationEndpoint;
    }

    public final String getResourceManagerEndpoint() {
        return data.resourceManagerEndpoint;
    }

    public final String getGraphEndpoint() {
        return data.graphEndpoint;

    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override
        public final String getDisplayName() {
            return "Microsoft Azure Service Principal";
        }

        public final String getDefaultServiceManagementURL() {
            return Constants.DEFAULT_MANAGEMENT_URL;
        }

        public final String getDefaultAuthenticationEndpoint() {
            return Constants.DEFAULT_AUTHENTICATION_ENDPOINT;
        }

        public final String getDefaultResourceManagerEndpoint() {
            return Constants.DEFAULT_RESOURCE_MANAGER_ENDPOINT;
        }

        public final String getDefaultGraphEndpoint() {
            return Constants.DEFAULT_GRAPH_ENDPOINT;
        }

        public final FormValidation doVerifyConfiguration(
                @QueryParameter final String subscriptionId,
                @QueryParameter final String clientId,
                @QueryParameter final String clientSecret,
                @QueryParameter final String oauth2TokenEndpoint,
                @QueryParameter final String serviceManagementURL,
                @QueryParameter final String authenticationEndpoint,
                @QueryParameter final String resourceManagerEndpoint,
                @QueryParameter final String graphEndpoint) {

            AzureCredentials.ServicePrincipal servicePrincipal
                    = new AzureCredentials.ServicePrincipal(
                    subscriptionId,
                    clientId,
                    clientSecret,
                    oauth2TokenEndpoint,
                    serviceManagementURL,
                    authenticationEndpoint,
                    resourceManagerEndpoint,
                    graphEndpoint);
            try {
                servicePrincipal.validate();
            } catch (ValidationException e) {
                return FormValidation.error(e.getMessage());
            }

            return FormValidation.ok(Messages.Azure_Config_Success());
        }

    }
}
