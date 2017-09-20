package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import hudson.Extension;
import org.kohsuke.stapler.DataBoundConstructor;

public class AzureMsiCredentials extends BaseStandardCredentials {

    public static final int DEFAULT_MSI_PORT = 50342;
    private final int msiPort;

    @DataBoundConstructor
    public AzureMsiCredentials(CredentialsScope scope, String id, String description, int msiPort) {
        super(scope, id, description);
        this.msiPort = msiPort;
    }

    public int getMsiPort() {
        return msiPort;
    }

    @Extension
    public static class DescriptorImpl
            extends BaseStandardCredentials.BaseStandardCredentialsDescriptor {

        @Override
        public String getDisplayName() {
            return "Microsoft Azure Managed Service Identity";
        }

        public int getDefaultMsiPort() {
            return DEFAULT_MSI_PORT;
        }
    }
}
