/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.util.AzureCredentials;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;

public class BaseSecretCredentials extends BaseStandardCredentials {

    private static final long serialVersionUID = 1L;

    private transient SecretGetter secretGetter;
    private final String credentialId;
    private final String secretIdentifier;

    public BaseSecretCredentials(CredentialsScope scope,
                                 String id,
                                 String description,
                                 String credentialId,
                                 String secretIdentifier) {
        super(scope, id, description);
        this.secretGetter = SecretGetter.DEFAULT;
        this.credentialId = credentialId;
        this.secretIdentifier = secretIdentifier;
    }

    /**
     * @deprecated use {@link #getCredentialId()}
     */
    @Deprecated
    public String getServicePrincipalId() {
        return this.credentialId;
    }

    public String getCredentialId() {
        return this.credentialId;
    }

    public String getSecretIdentifier() {
        return this.secretIdentifier;
    }

    protected SecretBundle getKeyVaultSecret() {
        if (this.secretGetter == null) {
            this.secretGetter = SecretGetter.DEFAULT;
        }
        return this.secretGetter.getKeyVaultSecret(credentialId, secretIdentifier);
    }

    @VisibleForTesting
    void setSecretGetter(SecretGetter secretGetter) {
        this.secretGetter = secretGetter;
    }

    interface SecretGetter {
        SecretBundle getKeyVaultSecret(String pCredentialId, String aSecretIdentifier);

        SecretGetter DEFAULT = new SecretGetter() {

            @Override
            public SecretBundle getKeyVaultSecret(String pCredentialId, String aSecretIdentifier) {
                KeyVaultCredentials keyVaultCredentials = AzureCredentials.getCredentialById(pCredentialId);
                final KeyVaultClient client = new KeyVaultClient(keyVaultCredentials);

                SecretBundle secret = client.getSecret(aSecretIdentifier);
                client.httpClient().connectionPool().evictAll();
                return secret;
            }
        };
    }

    protected abstract static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        public ListBoxModel doFillServicePrincipalIdItems(Item owner) {
            return new StandardListBoxModel()
                    .includeEmptyValue()
                    .includeAs(ACL.SYSTEM, owner, AzureCredentials.class);
        }
    }
}
