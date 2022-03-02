package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import hudson.Extension;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jenkinsci.plugins.pipeline.modeldefinition.model.CredentialsBindingHandler;

import edu.umd.cs.findbugs.annotations.NonNull;

@Extension(optional = true)
public class AzureCredentialsHandler extends CredentialsBindingHandler<StandardUsernamePasswordCredentials> {

    @NonNull
    @Override
    public Class<? extends StandardCredentials> type() {
        return AzureCredentials.class;
    }

    @NonNull
    @Override
    public List<Map<String, Object>> getWithCredentialsParameters(String credentialsId) {
        Map<String, Object> map = new HashMap<>();
        map.put("$class", AzureCredentialsBinding.class.getName());
        map.put("clientIdVariable", new EnvVarResolver("%s_CLIENT_ID"));
        map.put("clientSecretVariable", new EnvVarResolver("%s_CLIENT_SECRET"));
        map.put("subscriptionIdVariable", new EnvVarResolver("%s_SUBSCRIPTION_ID"));
        map.put("tenantIdVariable", new EnvVarResolver("%s_TENANT_ID"));
        map.put("credentialsId", credentialsId);
        return Collections.singletonList(map);
    }
}
