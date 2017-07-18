/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.jenkins.keyvault;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.models.SecretBundle;
import com.microsoft.azure.util.AzureCredentials;
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;

public class KeyVaultSecretCredentials extends BaseStandardCredentials implements StringCredentials {

    private final String servicePrincipalId;
    private final String secretIdentifier;

    @DataBoundConstructor
    public KeyVaultSecretCredentials(final CredentialsScope scope,
                                     final String id,
                                     final String description,
                                     final String servicePrincipalId,
                                     final String secretIdentifier) {
        super(scope, id, description);
        this.servicePrincipalId = servicePrincipalId;
        this.secretIdentifier = secretIdentifier;
    }

    public String getServicePrincipalId() {
        return this.servicePrincipalId;
    }

    public String getSecretIdentifier() {
        return this.secretIdentifier;
    }

    @Nonnull
    @Override
    public Secret getSecret() {
        final AzureCredentials.ServicePrincipal servicePrincipal =
                AzureCredentials.getServicePrincipal(servicePrincipalId);

        final KeyVaultClient client = new KeyVaultClient(new KeyVaultClientAuthenticator(
                servicePrincipal.getClientId(), servicePrincipal.getClientSecret()));

        final SecretBundle secretBundle = client.getSecret(secretIdentifier);
        return Secret.fromString(secretBundle.value());
    }

    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.Azure_KeyVault_Secret_Credentials_Diaplay_Name();
        }

        public ListBoxModel doFillServicePrincipalIdItems(final Item owner) {
            return new StandardListBoxModel()
                    .includeEmptyValue()
                    .includeAs(ACL.SYSTEM, owner, AzureCredentials.class);
        }
    }
}
