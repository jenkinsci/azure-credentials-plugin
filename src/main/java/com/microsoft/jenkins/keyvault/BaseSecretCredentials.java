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
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.util.AzureCredentials;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;

public class BaseSecretCredentials extends BaseStandardCredentials {

    private transient SecretGetter secretGetter;
    protected final String servicePrincipalId;
    protected final String secretIdentifier;

    public BaseSecretCredentials(final CredentialsScope scope,
                                 final String id,
                                 final String description,
                                 final String servicePrincipalId,
                                 final String secretIdentifier) {
        super(scope, id, description);
        this.secretGetter = SecretGetter.DEFAULT;
        this.servicePrincipalId = servicePrincipalId;
        this.secretIdentifier = secretIdentifier;
    }

    public String getServicePrincipalId() {
        return this.servicePrincipalId;
    }

    public String getSecretIdentifier() {
        return this.secretIdentifier;
    }

    protected SecretBundle getKeyVaultSecret() {
        if (this.secretGetter == null) {
            this.secretGetter = SecretGetter.DEFAULT;
        }
        return this.secretGetter.getKeyVaultSecret(servicePrincipalId, secretIdentifier);
    }

    @VisibleForTesting
    void setSecretGetter(final SecretGetter secretGetter) {
        this.secretGetter = secretGetter;
    }

    interface SecretGetter {
        SecretBundle getKeyVaultSecret(final String aServicePrincipalId, final String aSecretIdentifier);

        SecretGetter DEFAULT = new SecretGetter() {

            @Override
            public SecretBundle getKeyVaultSecret(final String aServicePrincipalId, final String aSecretIdentifier) {
                final AzureCredentials.ServicePrincipal servicePrincipal =
                        AzureCredentials.getServicePrincipal(aServicePrincipalId);

                final KeyVaultClient client = new KeyVaultClient(new KeyVaultClientAuthenticator(
                        servicePrincipal.getClientId(), servicePrincipal.getClientSecret()));

                return client.getSecret(aSecretIdentifier);
            }
        };
    }

    protected abstract static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        public ListBoxModel doFillServicePrincipalIdItems(final Item owner) {
            return new StandardListBoxModel()
                    .includeEmptyValue()
                    .includeAs(ACL.SYSTEM, owner, AzureCredentials.class);
        }
    }
}
