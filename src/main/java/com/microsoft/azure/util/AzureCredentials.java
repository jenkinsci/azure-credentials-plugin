/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.microsoft.azure.AzureEnvironment;
import com.microsoft.azure.credentials.ApplicationTokenCredentials;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.management.Azure;
import com.microsoft.azure.management.resources.Subscription;
import com.microsoft.jenkins.azurecommons.core.credentials.TokenCredentialData;
import com.microsoft.jenkins.keyvault.KeyVaultClientAuthenticator;
import com.microsoft.jenkins.keyvault.KeyVaultImdsAuthenticator;
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nullable;
import java.io.ObjectStreamException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class AzureCredentials extends AzureBaseCredentials {
    public static class ValidationException extends Exception {

        public ValidationException(String message) {
            super(message);
        }
    }

    public static class ServicePrincipal implements java.io.Serializable {
        private static final long serialVersionUID = 1L;

        private final Secret subscriptionId;
        private final Secret clientId;
        private final Secret clientSecret;
        /**
         * The ID of the PKCS#12 certificate stored in Jenkins master.
         * Used for authentication if {@link #clientSecret} is not provided.
         */
        private String certificateId;
        private Secret oauth2TokenEndpoint; //keeping this for backwards compatibility
        private String serviceManagementURL;
        private Secret tenant;
        private String authenticationEndpoint;
        private String resourceManagerEndpoint;
        private String graphEndpoint;

        /**
         * Name of the Azure Environment.
         * <p>
         * Added in the migration to Azure SDK 1.3.0.
         */
        private String azureEnvironmentName;

        /**
         * Cache of the resolved azure environment.
         * <p>
         * This should be cleared whenever the {@link #azureEnvironmentName}, or any of the endpoint override
         * is updated.
         */
        private transient AzureEnvironment azureEnvironment;

        /**
         * After deserialization hook to upgrade legacy service principal data.
         * <p>
         * XStream serialization / deserialization used by Jenkins doesn't support objects with  readObject/writeObject
         * defined.
         */
        private Object readResolve() throws ObjectStreamException {
            if (StringUtils.isNotBlank(azureEnvironmentName)) {
                // we have already migrated to the latest format, skip the resolving.
                return this;
            }

            Map<String, AzureEnvironment> environmentMap = new HashMap<>();
            environmentMap.put(AzureEnvUtil.Constants.ENV_AZURE, AzureEnvironment.AZURE);
            environmentMap.put(AzureEnvUtil.Constants.ENV_AZURE_CHINA, AzureEnvironment.AZURE_CHINA);
            environmentMap.put(AzureEnvUtil.Constants.ENV_AZURE_GERMANY, AzureEnvironment.AZURE_GERMANY);
            environmentMap.put(AzureEnvUtil.Constants.ENV_AZURE_US_GOVERNMENT, AzureEnvironment.AZURE_US_GOVERNMENT);

            // If the environment name is not recognized, which may happen when the user upgraded the plugin
            // and didn't update the credentials, we try to match a known environment.
            boolean matched = false;
            for (Map.Entry<String, AzureEnvironment> entry : environmentMap.entrySet()) {
                if (matchEnvironment(entry.getValue())) {
                    azureEnvironmentName = entry.getKey();

                    // user hasn't modified the default endpoint URL's, so we clear them so as to pick up the defaults
                    // in the environments.
                    serviceManagementURL = null;
                    authenticationEndpoint = null;
                    resourceManagerEndpoint = null;
                    graphEndpoint = null;

                    matched = true;
                    break;
                }
            }

            if (!matched) {
                azureEnvironmentName = AzureEnvUtil.Constants.ENV_AZURE;
            }

            return this;
        }

        public String getSubscriptionId() {
            if (subscriptionId == null) {
                return "";
            } else {
                return subscriptionId.getPlainText();
            }
        }

        public String getClientId() {
            if (clientId == null) {
                return "";
            } else {
                return clientId.getPlainText();
            }
        }

        public String getClientSecret() {
            if (clientSecret == null) {
                return "";
            } else {
                return clientSecret.getPlainText();
            }
        }

        public String getCertificateId() {
            return certificateId;
        }

        public void setCertificateId(String certificateId) {
            this.certificateId = certificateId;
        }

        /**
         * Get the certificate configured in the Service Principal.
         * <p>
         * Return <code>null</code> if:
         * <ul>
         * <li><code>clientSecret</code> is not empty. <code>clientSecret</code> will be used if not empty.</li>
         * <li><code>certificateId</code> is empty or the given certificate is not found.</li>
         * </ul>
         * <p>
         * Note: Azure {@link ApplicationTokenCredentials} requires the raw bytes of the whole certificate, rather than
         * the key(s) returned from the KeyStore. We need to return {@link CertificateCredentialsImpl} which has the
         * <code>getKeyStoreSource()</code> method that returns the raw certificate.
         *
         * @return the certificate configured in the Service Principal.
         */
        @Nullable
        CertificateCredentialsImpl getCertificate() {
            if (StringUtils.isNotEmpty(clientSecret.getPlainText())) {
                return null;
            }
            if (StringUtils.isEmpty(certificateId)) {
                return null;
            }
            CertificateCredentialsImpl certificate = CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(
                            CertificateCredentialsImpl.class,
                            Jenkins.getInstance(),
                            ACL.SYSTEM,
                            Collections.<DomainRequirement>emptyList()),
                    CredentialsMatchers.withId(certificateId));
            return certificate;
        }

        @Nullable
        public byte[] getCertificateBytes() {
            CertificateCredentialsImpl certificate = getCertificate();
            if (certificate == null) {
                return null;
            }
            return certificate.getKeyStoreSource().getKeyStoreBytes();
        }

        @Nullable
        public String getCertificatePassword() {
            CertificateCredentialsImpl certificate = getCertificate();
            if (certificate == null) {
                return null;
            }
            return certificate.getPassword().getPlainText();
        }

        public String getTenant() {
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

        public String getEncryptTenant() {
            if (tenant == null || StringUtils.isBlank(tenant.getPlainText())) {
                return "";
            }
            return tenant.getEncryptedValue();
        }

        public String getAzureEnvironmentName() {
            return azureEnvironmentName;
        }

        public AzureEnvironment getAzureEnvironment() {
            if (azureEnvironment != null) {
                return azureEnvironment;
            }

            String envName = getAzureEnvironmentName();
            azureEnvironment = AzureEnvUtil.resolveAzureEnv(envName);

            AzureEnvUtil.resolveOverride(azureEnvironment,
                    AzureEnvironment.Endpoint.MANAGEMENT, serviceManagementURL);
            AzureEnvUtil.resolveOverride(azureEnvironment,
                    AzureEnvironment.Endpoint.ACTIVE_DIRECTORY, authenticationEndpoint);
            AzureEnvUtil.resolveOverride(azureEnvironment,
                    AzureEnvironment.Endpoint.RESOURCE_MANAGER, resourceManagerEndpoint);
            AzureEnvUtil.resolveOverride(azureEnvironment,
                    AzureEnvironment.Endpoint.GRAPH, graphEndpoint);
            return azureEnvironment;
        }

        /**
         * @deprecated Use {@link #getManagementEndpoint()}
         */
        @Deprecated
        public String getServiceManagementURL() {
            return getManagementEndpoint();
        }

        public String getManagementEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.managementEndpoint();
        }

        /**
         * @deprecated Use {@link #getActiveDirectoryEndpoint()}.
         */
        @Deprecated
        public String getAuthenticationEndpoint() {
            return getActiveDirectoryEndpoint();
        }

        public String getActiveDirectoryEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.activeDirectoryEndpoint();
        }

        public String getResourceManagerEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.resourceManagerEndpoint();
        }

        public String getGraphEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.graphEndpoint();
        }

        /**
         * For backward compatibility.
         *
         * @deprecated use tenant related methods instead
         */
        @Deprecated
        void setOauth2TokenEndpoint(String oauth2TokenEndpoint) {
            this.oauth2TokenEndpoint = null;
            if (StringUtils.isNotBlank(oauth2TokenEndpoint)) {
                this.tenant = Secret.fromString(ServicePrincipal.getTenantFromTokenEndpoint(oauth2TokenEndpoint));
            }
        }

        void setTenant(String tenant) {
            this.tenant = Secret.fromString(tenant);
            if (StringUtils.isNotBlank(this.tenant.getPlainText())) {
                this.oauth2TokenEndpoint = null;
            }
        }

        void setManagementEndpoint(String managementEndpoint) {
            this.serviceManagementURL = StringUtils.trimToNull(managementEndpoint);
            this.azureEnvironment = null;
        }

        void setActiveDirectoryEndpoint(String activeDirectoryEndpoint) {
            this.authenticationEndpoint = StringUtils.trimToNull(activeDirectoryEndpoint);
            this.azureEnvironment = null;
        }

        void setResourceManagerEndpoint(String resourceManagerEndpoint) {
            this.resourceManagerEndpoint = StringUtils.trimToNull(resourceManagerEndpoint);
            this.azureEnvironment = null;
        }

        void setGraphEndpoint(String graphEndpoint) {
            this.graphEndpoint = StringUtils.trimToNull(graphEndpoint);
            this.azureEnvironment = null;
        }

        void setAzureEnvironmentName(String azureEnvironmentName) {
            this.azureEnvironmentName = azureEnvironmentName;
            this.azureEnvironment = null;
        }

        private boolean matchEnvironment(AzureEnvironment env) {
            return !AzureEnvUtil.isOverridden(env.managementEndpoint(), serviceManagementURL)
                    && !AzureEnvUtil.isOverridden(env.resourceManagerEndpoint(), resourceManagerEndpoint)
                    && !AzureEnvUtil.isOverridden(env.activeDirectoryEndpoint(), authenticationEndpoint)
                    && !AzureEnvUtil.isOverridden(env.graphEndpoint(), graphEndpoint);
        }

        public ServicePrincipal(
                String subscriptionId,
                String clientId,
                String clientSecret) {
            this.subscriptionId = Secret.fromString(subscriptionId);
            this.clientId = Secret.fromString(clientId);
            this.clientSecret = Secret.fromString(clientSecret);
            this.tenant = Secret.fromString("");
        }

        /**
         * @deprecated leave for backward compatibility.
         */
        @Deprecated
        public ServicePrincipal(
                String subscriptionId,
                String clientId,
                String clientSecret,
                String oauth2TokenEndpoint,
                String serviceManagementURL,
                String authenticationEndpoint,
                String resourceManagerEndpoint,
                String graphEndpoint) {
            this.subscriptionId = Secret.fromString(subscriptionId);
            this.clientId = Secret.fromString(clientId);
            this.clientSecret = Secret.fromString(clientSecret);
            this.tenant = Secret.fromString(ServicePrincipal.getTenantFromTokenEndpoint(oauth2TokenEndpoint));
            this.serviceManagementURL = StringUtils.trimToNull(serviceManagementURL);
            this.authenticationEndpoint = StringUtils.trimToNull(authenticationEndpoint);
            this.resourceManagerEndpoint = StringUtils.trimToNull(resourceManagerEndpoint);
            this.graphEndpoint = StringUtils.trimToNull(graphEndpoint);
        }

        public ServicePrincipal() {
            this.subscriptionId = Secret.fromString("");
            this.clientId = Secret.fromString("");
            this.clientSecret = Secret.fromString("");
            this.tenant = Secret.fromString("");
        }

        public boolean isBlank() {
            return StringUtils.isBlank(subscriptionId.getPlainText())
                    || StringUtils.isBlank(clientId.getPlainText())
                    || StringUtils.isBlank(getTenant())
                    || StringUtils.isBlank(clientSecret.getPlainText());
        }

        public boolean validate() throws ValidationException {
            if (StringUtils.isBlank(subscriptionId.getPlainText())) {
                throw new ValidationException(Messages.Azure_SubscriptionID_Missing());
            }
            if (StringUtils.isBlank(clientId.getPlainText())) {
                throw new ValidationException(Messages.Azure_ClientID_Missing());
            }
            String secret = clientSecret.getPlainText();
            if (StringUtils.isEmpty(secret) && StringUtils.isBlank(certificateId)) {
                throw new ValidationException(Messages.Azure_ClientSecret_Missing());
            }
            if (StringUtils.isBlank(getTenant())) {
                throw new ValidationException(Messages.Azure_OAuthToken_Malformed());
            }

            try {
                final String credentialSubscriptionId = getSubscriptionId();

                Azure.Authenticated auth;

                if (StringUtils.isEmpty(secret)) {
                    CertificateCredentialsImpl certificate = getCertificate();
                    if (certificate == null) {
                        throw new ValidationException(Messages.Azure_ClientCertificate_NotFound());
                    }
                    byte[] certificateBytes = certificate.getKeyStoreSource().getKeyStoreBytes();
                    auth = Azure.authenticate(
                            new ApplicationTokenCredentials(
                                    getClientId(),
                                    getTenant(),
                                    certificateBytes,
                                    certificate.getPassword().getPlainText(),
                                    getAzureEnvironment()));
                } else {
                    auth = Azure.authenticate(
                            new ApplicationTokenCredentials(
                                    getClientId(),
                                    getTenant(),
                                    getClientSecret(),
                                    getAzureEnvironment()));
                }
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

        private static String getTenantFromTokenEndpoint(String oauth2TokenEndpoint) {
            if (!oauth2TokenEndpoint.matches(
                    "https{0,1}://[a-zA-Z0-9\\.]*/[a-z0-9\\-]*/?.*$")) {
                return "";
            } else {
                String[] parts = oauth2TokenEndpoint.split("/");
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
            CredentialsScope scope,
            String id,
            String description,
            String subscriptionId,
            String clientId,
            String clientSecret) {
        super(scope, id, description);
        data = new ServicePrincipal(subscriptionId, clientId, clientSecret);
    }

    /**
     * @deprecated Leave for backward compatibility.
     */
    @Deprecated
    public AzureCredentials(
            CredentialsScope scope,
            String id,
            String description,
            String subscriptionId,
            String clientId,
            String clientSecret,
            String oauth2TokenEndpoint,
            String serviceManagementURL,
            String authenticationEndpoint,
            String resourceManagerEndpoint,
            String graphEndpoint) {
        super(scope, id, description);
        data = new ServicePrincipal(subscriptionId, clientId, clientSecret);
        data.setTenant(ServicePrincipal.getTenantFromTokenEndpoint(oauth2TokenEndpoint));
        data.setManagementEndpoint(serviceManagementURL);
        data.setActiveDirectoryEndpoint(authenticationEndpoint);
        data.setResourceManagerEndpoint(resourceManagerEndpoint);
        data.setGraphEndpoint(graphEndpoint);
    }

    @Deprecated
    public static AzureCredentials.ServicePrincipal getServicePrincipal(
            String credentialsId) {
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

    public static KeyVaultCredentials getCredentialById(String credentialId) {
        AzureCredentials azureCredentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
        if (azureCredentials != null) {
            return new KeyVaultClientAuthenticator(azureCredentials.data.getClientId(),
                    azureCredentials.data.getClientSecret());
        }

        UsernamePasswordCredentials usernamePasswordCredentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        UsernamePasswordCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
        if (usernamePasswordCredentials != null) {
            return new KeyVaultClientAuthenticator(usernamePasswordCredentials.getUsername(),
                    usernamePasswordCredentials.getPassword().getPlainText());
        }

        AzureImdsCredentials imdsCredentials = CredentialsMatchers.firstOrNull(
                CredentialsProvider.lookupCredentials(
                        AzureImdsCredentials.class,
                        Jenkins.getInstance(),
                        ACL.SYSTEM,
                        Collections.<DomainRequirement>emptyList()),
                CredentialsMatchers.withId(credentialId));
        if (imdsCredentials != null) {
            return new KeyVaultImdsAuthenticator();
        }
        throw new RuntimeException(String.format("Credential: %s was not found", credentialId));
    }

    public String getSubscriptionId() {
        if (StringUtils.isEmpty(data.subscriptionId.getPlainText())) {
            return "";
        }
        return data.subscriptionId.getEncryptedValue();
    }

    public String getPlainSubscriptionId() {
        return data.subscriptionId.getPlainText();
    }

    public String getClientId() {
        if (StringUtils.isEmpty(data.clientId.getPlainText())) {
            return "";
        }
        return data.clientId.getEncryptedValue();
    }

    public String getPlainClientId() {
        return data.clientId.getPlainText();
    }

    public String getClientSecret() {
        if (StringUtils.isEmpty(data.clientSecret.getPlainText())) {
            return "";
        }
        return data.clientSecret.getEncryptedValue();
    }

    public String getPlainClientSecret() {
        return data.clientSecret.getPlainText();
    }

    @DataBoundSetter
    public void setCertificateId(String certificateId) {
        this.data.setCertificateId(certificateId);
    }

    public String getCertificateId() {
        return data.getCertificateId();
    }

    public String getTenant() {
        return data.getEncryptTenant();
    }

    public String getPlainTenant() {
        return data.getTenant();
    }

    @DataBoundSetter
    public void setTenant(String tenant) {
        this.data.setTenant(tenant);
    }

    /**
     * For backward compatibility.
     *
     * @deprecated use tenant related methods instead.
     */
    @Deprecated
    public String getOauth2TokenEndpoint() {
        return "https://login.windows.net/" + data.getTenant();
    }

    /**
     * Set the Oauth2 token endpoint for backward compatibility only.
     *
     * @param oauth2TokenEndpoint the endpoint value in the form "https://login.windows.net/&lt;TenantId&gt;"
     * @deprecated use tenant related methods instead.
     */
    @DataBoundSetter
    @Deprecated
    public void setOauth2TokenEndpoint(String oauth2TokenEndpoint) {
        this.data.setOauth2TokenEndpoint(oauth2TokenEndpoint);
    }

    /**
     * typo.
     */
    @Deprecated
    public String getAzureEnvionmentName() {
        return data.getAzureEnvironmentName();
    }

    @Override
    public String getAzureEnvironmentName() {
        return data.getAzureEnvironmentName();
    }

    @DataBoundSetter
    public void setAzureEnvironmentName(String azureEnvironmentName) {
        this.data.setAzureEnvironmentName(azureEnvironmentName);
    }

    /**
     * @deprecated use {@link #getManagementEndpoint()}.
     */
    @Deprecated
    public String getServiceManagementURL() {
        return getManagementEndpoint();
    }

    @Override
    public String getManagementEndpoint() {
        return data.serviceManagementURL;
    }

    /**
     * @deprecated use {@link #setManagementEndpoint(String)}.
     */
    @DataBoundSetter
    @Deprecated
    public void setServiceManagementURL(String serviceManagementURL) {
        setManagementEndpoint(serviceManagementURL);
    }

    @DataBoundSetter
    public void setManagementEndpoint(String managementEndpoint) {
        this.data.setManagementEndpoint(managementEndpoint);
    }

    /**
     * @deprecated use {@link #getActiveDirectoryEndpoint()}.
     */
    @Deprecated
    public String getAuthenticationEndpoint() {
        return getActiveDirectoryEndpoint();
    }

    @Override
    public String getActiveDirectoryEndpoint() {
        return data.authenticationEndpoint;
    }

    /**
     * @deprecated use {@link #setActiveDirectoryEndpoint(String)}.
     */
    @DataBoundSetter
    @Deprecated
    public void setAuthenticationEndpoint(String authenticationEndpoint) {
        setActiveDirectoryEndpoint(authenticationEndpoint);
    }

    @DataBoundSetter
    public void setActiveDirectoryEndpoint(String activeDirectoryEndpoint) {
        this.data.setActiveDirectoryEndpoint(activeDirectoryEndpoint);
    }

    @Override
    public String getResourceManagerEndpoint() {
        return data.resourceManagerEndpoint;
    }

    @DataBoundSetter
    public void setResourceManagerEndpoint(String resourceManagerEndpoint) {
        this.data.setResourceManagerEndpoint(resourceManagerEndpoint);
    }

    @Override
    public String getGraphEndpoint() {
        return data.graphEndpoint;
    }

    @Override
    public TokenCredentialData createToken() {
        TokenCredentialData token = super.createToken();
        token.setType(TokenCredentialData.TYPE_SP);
        token.setClientId(getPlainClientId());
        token.setClientSecret(getPlainClientSecret());
        token.setCertificateBytes(data.getCertificateBytes());
        token.setCertificatePassword(data.getCertificatePassword());
        token.setTenant(getPlainTenant());
        token.setSubscriptionId(getPlainSubscriptionId());
        return token;
    }

    @DataBoundSetter
    public void setGraphEndpoint(String graphEndpoint) {
        this.data.setGraphEndpoint(graphEndpoint);
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {
        public DescriptorImpl() {
            super();
            load();
        }

        @Override
        public String getDisplayName() {
            return "Microsoft Azure Service Principal";
        }

        public FormValidation doVerifyConfiguration(
                @QueryParameter String subscriptionId,
                @QueryParameter String clientId,
                @QueryParameter String clientSecret,
                @QueryParameter String certificateId,
                @QueryParameter String tenant,
                @QueryParameter String azureEnvironmentName,
                @QueryParameter String serviceManagementURL,
                @QueryParameter String authenticationEndpoint,
                @QueryParameter String resourceManagerEndpoint,
                @QueryParameter String graphEndpoint) {

            AzureCredentials.ServicePrincipal servicePrincipal
                    = new AzureCredentials.ServicePrincipal(subscriptionId, clientId, clientSecret);
            servicePrincipal.setCertificateId(certificateId);
            servicePrincipal.setTenant(tenant);
            servicePrincipal.setAzureEnvironmentName(azureEnvironmentName);
            servicePrincipal.setManagementEndpoint(serviceManagementURL);
            servicePrincipal.setActiveDirectoryEndpoint(authenticationEndpoint);
            servicePrincipal.setResourceManagerEndpoint(resourceManagerEndpoint);
            servicePrincipal.setGraphEndpoint(graphEndpoint);
            try {
                servicePrincipal.validate();
            } catch (ValidationException e) {
                return FormValidation.error(e.getMessage());
            }

            return FormValidation.ok(Messages.Azure_Config_Success());
        }

        public ListBoxModel doFillCertificateIdItems(@AncestorInPath Item owner) {
            StandardListBoxModel model = new StandardListBoxModel();
            model.add(Messages.Azure_Credentials_Select(), "");
            model.includeAs(ACL.SYSTEM, owner, CertificateCredentialsImpl.class);
            return model;
        }

        public ListBoxModel doFillAzureEnvironmentNameItems() {
            ListBoxModel model = new ListBoxModel();
            model.add(AzureEnvUtil.Constants.ENV_AZURE);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_CHINA);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_GERMANY);
            model.add(AzureEnvUtil.Constants.ENV_AZURE_US_GOVERNMENT);
            return model;
        }
    }
}
