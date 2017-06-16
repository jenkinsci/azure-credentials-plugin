/**
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See LICENSE file in the project root for license information.
 */
package com.microsoft.azure.util;

import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Custom binding for AzureCredentials to support reading Azure service principal in both freestyle
 * and pipeline using Credentials Binding plugin.
 * There're two ways to construct this binding:
 * 1. With defaults, which will read specified service principal into four predefined environment
 *    variables: AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID.
 *    Sample pipeline code:
 *      withCredentials([azureServicePrincipal('credentials_id')]) {
 *          sh 'az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET -t $AZURE_TENANT_ID'
 *      }
 * 2. With custom name, where you can control the names of the variables.
 *    Sample pipeline code:
 *      withCredentials([azureServicePrincipal(credentialsId: 'credentials_id',
 *                                        subscriptionIdVariable: 'SUBS_ID',
 *                                        clientIdVariable: 'CLIENT_ID',
 *                                        clientSecretVariable: 'CLIENT_SECRET',
 *                                        tenantIdVariable: 'TENANT_ID')]) {
 *          sh 'az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET -t $TENANT_ID'
 *      }
 */
public class AzureCredentialsBinding extends MultiBinding<AzureCredentials> {
    public static final String DEFAULT_SUBSCRIPTION_ID_VARIABLE = "AZURE_SUBSCRIPTION_ID";
    public static final String DEFAULT_CLIENT_ID_VARIABLE = "AZURE_CLIENT_ID";
    public static final String DEFAULT_CLIENT_SECRET_VARIABLE = "AZURE_CLIENT_SECRET";
    public static final String DEFAULT_TENANT_ID_VARIABLE = "AZURE_TENANT_ID";

    private String subscriptionIdVariable;
    private String clientIdVariable;
    private String clientSecretVariable;
    private String tenantIdVariable;

    @DataBoundConstructor
    public AzureCredentialsBinding(final String credentialsId) {
        super(credentialsId);
    }

    @DataBoundSetter
    public final void setSubscriptionIdVariable(final String subscriptionIdVariable) {
        this.subscriptionIdVariable = subscriptionIdVariable;
    }

    @DataBoundSetter
    public final void setClientIdVariable(final String clientIdVariable) {
        this.clientIdVariable = clientIdVariable;
    }

    @DataBoundSetter
    public final void setClientSecretVariable(final String clientSecretVariable) {
        this.clientSecretVariable = clientSecretVariable;
    }

    @DataBoundSetter
    public final void setTenantIdVariable(final String tenantIdVariable) {
        this.tenantIdVariable = tenantIdVariable;
    }

    public final String getSubscriptionIdVariable() {
        if (!StringUtils.isBlank(subscriptionIdVariable)) {
            return subscriptionIdVariable;
        }

        return DEFAULT_SUBSCRIPTION_ID_VARIABLE;
    }

    public final String getClientIdVariable() {
        if (!StringUtils.isBlank(clientIdVariable)) {
            return clientIdVariable;
        }

        return DEFAULT_CLIENT_ID_VARIABLE;
    }

    public final String getClientSecretVariable() {
        if (!StringUtils.isBlank(clientSecretVariable)) {
            return clientSecretVariable;
        }

        return DEFAULT_CLIENT_SECRET_VARIABLE;
    }

    public final String getTenantIdVariable() {
        if (!StringUtils.isBlank(tenantIdVariable)) {
            return tenantIdVariable;
        }

        return DEFAULT_TENANT_ID_VARIABLE;
    }

    @Override
    protected final Class<AzureCredentials> type() {
        return AzureCredentials.class;
    }

    @Override
    public final MultiEnvironment bind(@Nonnull final Run<?, ?> build,
                                       final FilePath workspace,
                                       final Launcher launcher,
                                       final TaskListener listener)
            throws IOException, InterruptedException {
        AzureCredentials credentials = getCredentials(build);
        Map<String, String> map = new HashMap<>();
        map.put(getSubscriptionIdVariable(), credentials.getSubscriptionId());
        map.put(getClientIdVariable(), credentials.getClientId());
        map.put(getClientSecretVariable(), credentials.getPlainClientSecret());
        map.put(getTenantIdVariable(), credentials.getTenant());
        return new MultiEnvironment(map);
    }

    @Override
    public final Set<String> variables() {
        return new HashSet<String>(Arrays.asList(
                getSubscriptionIdVariable(),
                getClientIdVariable(),
                getClientSecretVariable(),
                getTenantIdVariable()));
    }

    @Symbol("azureServicePrincipal")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<AzureCredentials> {
        @Override
        protected final Class<AzureCredentials> type() {
            return AzureCredentials.class;
        }

        @Override
        public final String getDisplayName() {
            return Messages.Azure_Credentials_Binding_Diaplay_Name();
        }

        @Override
        public final boolean requiresWorkspace() {
            return false;
        }

        public final String getDefaultSubscriptionIdVariable() {
            return DEFAULT_SUBSCRIPTION_ID_VARIABLE;
        }

        public final String getDefaultClientIdVariable() {
            return DEFAULT_CLIENT_ID_VARIABLE;
        }

        public final String getDefaultClientSecretVariable() {
            return DEFAULT_CLIENT_SECRET_VARIABLE;
        }

        public final String getDefaultTenantIdVariable() {
            return DEFAULT_TENANT_ID_VARIABLE;
        }
    }
}
