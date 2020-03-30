/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */

package com.microsoft.jenkins.keyvault;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class SecretStringCredentialsTest {

    @ClassRule
    public static JenkinsRule j = new JenkinsRule();

    @Test
    public void getSecret() {
        final BaseSecretCredentials.SecretGetter secretGetter = new BaseSecretCredentials.SecretGetter() {
            @Override
            public KeyVaultSecret getKeyVaultSecret(String credentialId, String secretIdentifier) {
                Assert.assertEquals("spId", credentialId);
                Assert.assertEquals("secretId", secretIdentifier);

                final KeyVaultSecret secretBundle = new KeyVaultSecret("name", "Secret");

                return secretBundle;
            }
        };
        final SecretStringCredentials c = new SecretStringCredentials(
                CredentialsScope.SYSTEM,
                "id",
                "desc",
                "spId",
                "secretId"
        );
        c.setSecretGetter(secretGetter);

        final Secret secret = c.getSecret();
        Assert.assertEquals("Secret", secret.getPlainText());
    }

    @Test
    public void descriptorVerifyConfiguration() {
        final SecretStringCredentials.DescriptorImpl descriptor = new SecretStringCredentials.DescriptorImpl();

        FormValidation result = descriptor.doVerifyConfiguration("", "");
        Assert.assertEquals(FormValidation.Kind.ERROR, result.kind);
    }

}
