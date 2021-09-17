/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.google.common.annotations.VisibleForTesting;
import com.microsoft.azure.util.AzureCredentials;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import java.net.MalformedURLException;
import java.net.URL;

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

    protected KeyVaultSecret getKeyVaultSecret() {
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
        KeyVaultSecret getKeyVaultSecret(String pCredentialId, String aSecretIdentifier);

        int NAME_POSITION = 2;
        int VERSION_POSITION = 3;
        SecretGetter DEFAULT = (pCredentialId, aSecretIdentifier) -> {
            SecretClient client;
            URL secretIdentifierUrl;
            try {
                secretIdentifierUrl = new URL(aSecretIdentifier);
                client = SecretClientCache.get(pCredentialId, "https://" + secretIdentifierUrl.getHost());
            } catch (MalformedURLException e) {
                throw new RuntimeException(e);
            }

            // old SDK supports secret identifier which is a full URI to the secret
            // the new SDK doesn't seem to support it to we parse it to get the values we need
            // https://mine.vault.azure.net/secrets/<name>/<version>
            String[] split = secretIdentifierUrl.getPath().split("/");

            if (split.length == NAME_POSITION + 1) {
                return client.getSecret(split[NAME_POSITION]);
            }
            return client.getSecret(split[NAME_POSITION], split[VERSION_POSITION]);
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
