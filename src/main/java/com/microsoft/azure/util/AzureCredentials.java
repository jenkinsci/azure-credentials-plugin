/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.azure.util;

import com.azure.core.credential.TokenCredential;
import com.azure.core.management.AzureEnvironment;
import com.azure.core.management.profile.AzureProfile;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.identity.implementation.IdentityClientOptions;
import com.azure.resourcemanager.AzureResourceManager;
import com.azure.resourcemanager.resources.models.Subscription;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl;
import com.microsoft.jenkins.credentials.AzureResourceManagerCache;
import com.microsoft.jenkins.keyvault.SecretClientCache;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import io.jenkins.plugins.azuresdk.HttpClientRetriever;
import java.util.List;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

import edu.umd.cs.findbugs.annotations.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ObjectStreamException;
import java.util.Collections;

public class AzureCredentials extends AzureBaseCredentials {
    public static class ValidationException extends Exception {

        public ValidationException(String message) {
            super(message);
        }

        public ValidationException(String message, Throwable cause) {
            super(message, cause);
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
            return CredentialsMatchers.firstOrNull(
                    CredentialsProvider.lookupCredentials(
                            CertificateCredentialsImpl.class,
                            Jenkins.get(),
                            ACL.SYSTEM,
                            Collections.emptyList()),
                    CredentialsMatchers.withId(certificateId));
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
            return env.getManagementEndpoint();
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
            return env.getActiveDirectoryEndpoint();
        }

        public String getResourceManagerEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.getResourceManagerEndpoint();
        }

        public String getGraphEndpoint() {
            AzureEnvironment env = getAzureEnvironment();
            return env.getGraphEndpoint();
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

        public ServicePrincipal(
                String subscriptionId,
                String clientId,
                Secret clientSecret) {
            this.subscriptionId = Secret.fromString(subscriptionId);
            this.clientId = Secret.fromString(clientId);
            this.clientSecret = clientSecret;
            this.tenant = Secret.fromString("");
        }

        @Deprecated
        public ServicePrincipal(
                String subscriptionId,
                String clientId,
                String clientSecret) {
            this(subscriptionId, clientId, Secret.fromString(clientSecret));
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

                AzureProfile profile = new AzureProfile(getAzureEnvironment());
                TokenCredential credential;

                if (StringUtils.isEmpty(secret)) {
                    CertificateCredentialsImpl certificate = getCertificate();
                    if (certificate == null) {
                        throw new ValidationException(Messages.Azure_ClientCertificate_NotFound());
                    }
                    ByteArrayInputStream certificateBytes = new ByteArrayInputStream(
                            certificate.getKeyStoreSource().getKeyStoreBytes()
                    );

                    IdentityClientOptions identityClientOptions = new IdentityClientOptions();
                    identityClientOptions.setHttpClient(HttpClientRetriever.get());

                    credential = new ClientCertificateCredential2(
                            getTenant(),
                            getClientId(),
                            null,
                            // this is package-private in the default sdk method which is why we have our own class
                            certificateBytes,
                            certificate.getPassword().getPlainText(),
                            identityClientOptions);
                } else {
                    credential = new ClientSecretCredentialBuilder()
                            .authorityHost(profile.getEnvironment().getActiveDirectoryEndpoint())
                            .clientId(getClientId())
                            .clientSecret(getClientSecret())
                            .tenantId(getTenant())
                            .httpClient(HttpClientRetriever.get())
                            .build();
                }

                AzureResourceManager azure = AzureResourceManager
                        .configure()
                        .withHttpClient(HttpClientRetriever.get())
                        .authenticate(credential, profile)
                        .withSubscription(subscriptionId.getPlainText());

                for (Subscription subscription : azure.subscriptions().list()) {
                    if (subscription.subscriptionId().equalsIgnoreCase(credentialSubscriptionId)) {
                        return true;
                    }
                }
            } catch (Exception e) {
                throw new ValidationException(Messages.Azure_CantValidate() + ": " + e.getMessage(), e);
            }
            throw new ValidationException(Messages.Azure_Invalid_SubscriptionId());
        }

        private static final int TOKEN_ENDPOINT_URL_ENDPOINT_POSTION = 3;

        private static String getTenantFromTokenEndpoint(String oauth2TokenEndpoint) {
            if (!oauth2TokenEndpoint.matches(
                    "https{0,1}://[a-zA-Z0-9.]*/[a-z0-9\\-]*/?.*$")) {
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

    @Deprecated
    public AzureCredentials(
            CredentialsScope scope,
            String id,
            String description,
            String subscriptionId,
            String clientId,
            String clientSecret) {
        super(scope, id, description);
        data = new ServicePrincipal(subscriptionId, clientId, Secret.fromString(clientSecret));
    }

    @DataBoundConstructor
    public AzureCredentials(
            CredentialsScope scope,
            String id,
            String description,
            String subscriptionId,
            String clientId,
            Secret clientSecret) {
        super(scope, id, description);
        data = new ServicePrincipal(subscriptionId, clientId, clientSecret);
        SecretClientCache.invalidateCache();
        AzureResourceManagerCache.invalidateCache();
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
        data = new ServicePrincipal(subscriptionId, clientId, Secret.fromString(clientSecret));
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
                        Collections.emptyList()),
                CredentialsMatchers.withId(credentialsId));
        if (creds == null) {
            return new AzureCredentials.ServicePrincipal();
        }
        return creds.data;
    }

    public static SecretClient createKeyVaultClient(TokenCredential credential, String keyVaultUrl) {
        return new SecretClientBuilder()
                .vaultUrl(keyVaultUrl)
                .credential(credential)
                .httpClient(HttpClientRetriever.get())
                .buildClient();
    }

    /**
     * Only checks the system provider for credentials.
     * Use if you need to bypass other providers, e.g. in a credential provider.
     */
    public static TokenCredential getSystemCredentialById(String credentialID) {
        if (StringUtils.isEmpty(credentialID)) {
            return null;
        }
        SystemCredentialsProvider systemCredentialsProvider = SystemCredentialsProvider.getInstance();
        List<AzureImdsCredentials> azureImdsCredentials =
            DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                AzureImdsCredentials.class,
                Collections.emptyList(),
                CredentialsMatchers.withId(credentialID));

        if (!azureImdsCredentials.isEmpty()) {
            AzureImdsCredentials azureIdmsCredential = azureImdsCredentials.get(0);
            ManagedIdentityCredentialBuilder credentialBuilder = new ManagedIdentityCredentialBuilder();

            if (azureIdmsCredential.isUserAssigned()) {
                credentialBuilder.clientId(azureIdmsCredential.getClientId());
            }

            return credentialBuilder.build();
        }

        List<AzureCredentials> azureCredentials =
            DomainCredentials.getCredentials(systemCredentialsProvider.getDomainCredentialsMap(),
                AzureCredentials.class,
                Collections.emptyList(),
                CredentialsMatchers.withId(credentialID));

        ClientSecretCredential credential = null;
        if (!azureCredentials.isEmpty()) {
            AzureCredentials azureCredential = azureCredentials.get(0);

            credential = new ClientSecretCredentialBuilder()
                .clientId(azureCredential.getClientId())
                .clientSecret(azureCredential.getPlainClientSecret())
                .httpClient(HttpClientRetriever.get())
                .tenantId(azureCredential.getTenant())
                .build();
        }

        if (credential == null) {
            throw new RuntimeException(String.format("Credential: %s was not found for supported credentials "
                + "type.", credentialID));
        }
        return credential;
    }


    public static TokenCredential getTokenCredential(AzureBaseCredentials credentials) {
        if (credentials instanceof AzureCredentials) {
            AzureCredentials azureCredentials = (AzureCredentials) credentials;

            return new ClientSecretCredentialBuilder()
                    .clientId(azureCredentials.getClientId())
                    .clientSecret(azureCredentials.getPlainClientSecret())
                    .tenantId(azureCredentials.getTenant())
                    .authorityHost(azureCredentials.getAzureEnvironment().getActiveDirectoryEndpoint())
                    .httpClient(HttpClientRetriever.get())
                    .build();
        }

        if (credentials instanceof AzureImdsCredentials) {
            AzureImdsCredentials idmsCredentials = (AzureImdsCredentials) credentials;

            ManagedIdentityCredentialBuilder credentialBuilder = new ManagedIdentityCredentialBuilder()
                .httpClient(HttpClientRetriever.get());

            if (idmsCredentials.isUserAssigned()) {
                credentialBuilder.clientId(idmsCredentials.getClientId());
            }

            return credentialBuilder.build();
        }
        throw new RuntimeException(String.format("Unsupported credential: %s", credentials.getId()));
    }

    public static TokenCredential getCredentialById(Item owner, String credentialId) {
        return getTokenCredential(AzureCredentialUtil.getCredential(owner, credentialId));
    }

    @Override
    public String getSubscriptionId() {
        return data.subscriptionId.getPlainText();
    }

    public String getClientId() {
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
    public AzureEnvironment getAzureEnvironment() {
        return data.getAzureEnvironment();
    }

    @Override
    public String getGraphEndpoint() {
        return data.graphEndpoint;
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
        @NonNull
        public String getDisplayName() {
            return "Azure Service Principal";
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
                    = new AzureCredentials.ServicePrincipal(subscriptionId, clientId, Secret.fromString(clientSecret));
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
                return FormValidation.error(e, e.getMessage());
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
