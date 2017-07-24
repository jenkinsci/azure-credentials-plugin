/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.jenkins.keyvault;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.azure.keyvault.models.SecretBundle;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.annotation.Nonnull;

public class SecretStringCredentials extends BaseSecretCredentials implements StringCredentials {

    @DataBoundConstructor
    public SecretStringCredentials(final CredentialsScope scope,
                                   final String id,
                                   final String description,
                                   final String servicePrincipalId,
                                   final String secretIdentifier) {
        super(scope, id, description, servicePrincipalId, secretIdentifier);
    }

    @Nonnull
    @Override
    public Secret getSecret() {
        final SecretBundle secretBundle = getKeyVaultSecret();
        return Secret.fromString(secretBundle.value());
    }

    @Extension
    public static class DescriptorImpl extends BaseSecretCredentials.DescriptorImpl {

        @Override
        public String getDisplayName() {
            return Messages.String_Credentials_Diaplay_Name();
        }

        public final FormValidation doVerifyConfiguration(
                @QueryParameter final String servicePrincipalId,
                @QueryParameter final String secretIdentifier) {

            final SecretStringCredentials credentials = new SecretStringCredentials(
                    CredentialsScope.SYSTEM, "", "", servicePrincipalId, secretIdentifier);

            try {
                credentials.getSecret();
            } catch (Exception e) {
                String message = e.getMessage();
                if (message == null) {
                    message = Messages.String_Credentials_Validation_Invalid();
                }
                return FormValidation.error(message);
            }

            return FormValidation.ok(Messages.String_Credentials_Validation_OK());
        }

    }
}
