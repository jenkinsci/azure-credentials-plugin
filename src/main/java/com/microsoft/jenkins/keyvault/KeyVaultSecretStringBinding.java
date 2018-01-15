/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.Binding;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;

public class KeyVaultSecretStringBinding extends Binding<SecretStringCredentials> {
    public static final String DEFAULT_VARIABLE = "KEY_VAULT_SECRET";

    @DataBoundConstructor
    public KeyVaultSecretStringBinding(String variable, String credentialsId) {
        super(StringUtils.isBlank(variable) ? DEFAULT_VARIABLE : variable.trim(), credentialsId);
    }

    @Override
    protected Class<SecretStringCredentials> type() {
        return SecretStringCredentials.class;
    }

    @Override
    public SingleEnvironment bindSingle(@Nonnull Run<?, ?> build,
                                        @Nullable FilePath workspace,
                                        @Nullable Launcher launcher,
                                        @Nonnull TaskListener listener) throws IOException, InterruptedException {
        SecretStringCredentials credentials = getCredentials(build);
        return new SingleEnvironment(credentials.getSecret().getPlainText());
    }

    @Symbol("azureKeyVaultSecretString")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<SecretStringCredentials> {
        @Override
        protected Class<SecretStringCredentials> type() {
            return SecretStringCredentials.class;
        }

        @Override
        public String getDisplayName() {
            return Messages.Azure_Key_Vault_Secret_String_Binding_Display_Name();
        }

        @Override
        public boolean requiresWorkspace() {
            return false;
        }

        public String getDefaultVariable() {
            return DEFAULT_VARIABLE;
        }
    }
}
