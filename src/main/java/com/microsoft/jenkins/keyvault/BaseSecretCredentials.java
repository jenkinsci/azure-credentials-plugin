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

    private static final long serialVersionUID = 1L;

    private transient SecretGetter secretGetter;
    private final String servicePrincipalId;
    private final String secretIdentifier;

    public BaseSecretCredentials(CredentialsScope scope,
                                 String id,
                                 String description,
                                 String servicePrincipalId,
                                 String secretIdentifier) {
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
    void setSecretGetter(SecretGetter secretGetter) {
        this.secretGetter = secretGetter;
    }

    interface SecretGetter {
        SecretBundle getKeyVaultSecret(String aServicePrincipalId, String aSecretIdentifier);

        SecretGetter DEFAULT = new SecretGetter() {

            @Override
            public SecretBundle getKeyVaultSecret(String aServicePrincipalId, String aSecretIdentifier) {
                final AzureCredentials.ServicePrincipal servicePrincipal =
                        AzureCredentials.getServicePrincipal(aServicePrincipalId);

                final KeyVaultClient client = new KeyVaultClient(new KeyVaultClientAuthenticator(
                        servicePrincipal.getClientId(), servicePrincipal.getClientSecret()));

                return client.getSecret(aSecretIdentifier);
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
