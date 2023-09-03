/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.jenkins.keyvault;

import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardCertificateCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.verb.POST;

public class SecretCertificateCredentials extends BaseSecretCredentials implements StandardCertificateCredentials {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(SecretCertificateCredentials.class.getName());

    private final Secret password;

    @DataBoundConstructor
    public SecretCertificateCredentials(
            CredentialsScope scope,
            String id,
            String description,
            String servicePrincipalId,
            String secretIdentifier,
            Secret password) {
        super(scope, id, description, servicePrincipalId, secretIdentifier);
        this.password = password;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return password;
    }

    /**
     * Helper to convert a {@link Secret} password into a {@code char[]}.
     *
     * @param password the password.
     * @return a {@code char[]} containing the password or {@code null}
     */
    @CheckForNull
    private static char[] toCharArray(@NonNull Secret password) {
        String plainText = Util.fixEmpty(password.getPlainText());
        if (plainText == null) {
            return null;
        } else {
            return plainText.toCharArray();
        }
    }

    @NonNull
    @Override
    public KeyStore getKeyStore() {
        final KeyVaultSecret secret = getKeyVaultSecret();

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            throw new IllegalStateException("PKCS12 is a keystore type per the JLS spec", e);
        }

        try {
            final byte[] content = Base64.getMimeDecoder().decode(secret.getValue());
            keyStore.load(new ByteArrayInputStream(content), toCharArray(password));
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            final LogRecord lr = new LogRecord(Level.WARNING, "Credentials ID {0}: Could not load keystore from {1}");
            lr.setParameters(new Object[] {getId(), getSecretIdentifier()});
            lr.setThrown(e);
            LOGGER.log(lr);
        }

        return keyStore;
    }

    @Extension
    public static class DescriptorImpl extends BaseSecretCredentials.DescriptorImpl {

        @Override
        public String getDisplayName() {
            return Messages.Certificate_Credentials_Display_Name();
        }

        @POST
        public FormValidation doVerifyConfiguration(
                @AncestorInPath Item owner,
                @QueryParameter String servicePrincipalId,
                @QueryParameter String secretIdentifier,
                @QueryParameter Secret password) {
            if (owner == null) {
                Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            } else {
                owner.checkPermission(Item.CONFIGURE);
            }

            final SecretCertificateCredentials credentials = new SecretCertificateCredentials(
                    CredentialsScope.SYSTEM, "", "", servicePrincipalId, secretIdentifier, password);

            KeyStore keyStore;
            try {
                keyStore = credentials.getKeyStore();
            } catch (Exception e) {
                String message = e.getMessage();
                if (message == null) {
                    message = Messages.Certificate_Credentials_Validation_Invalid();
                }
                return FormValidation.error(message);
            }

            try {
                final Enumeration<String> aliases = keyStore.aliases();
                if (!aliases.hasMoreElements()) {
                    return FormValidation.error(Messages.Certificate_Credentials_Validation_No_Private_Key());
                }
            } catch (KeyStoreException e) {
                return FormValidation.error(e.getMessage());
            }

            return FormValidation.ok(Messages.Certificate_Credentials_Validation_OK());
        }
    }
}
