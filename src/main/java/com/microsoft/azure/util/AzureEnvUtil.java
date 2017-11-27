package com.microsoft.azure.util;

import com.microsoft.azure.AzureEnvironment;
import org.apache.commons.lang.StringUtils;

import java.util.HashMap;

public final class AzureEnvUtil {
    static boolean resolveOverride(
            AzureEnvironment environment, AzureEnvironment.Endpoint endpoint, String stored) {
        if (StringUtils.isBlank(stored)) {
            return false;
        }
        String defaultValue = environment.endpoints().get(endpoint.identifier());
        if (StringUtils.isBlank(defaultValue)) {
            // should not happen
            environment.endpoints().put(endpoint.identifier(), stored);
            return true;
        }
        if (isOverridden(defaultValue, stored)) {
            environment.endpoints().put(endpoint.identifier(), stored);
            return true;
        }
        return false;
    }

    static boolean isOverridden(String defaultURL, String overrideURL) {
        return StringUtils.isNotBlank(overrideURL)
                && !defaultURL.replaceAll("/+$", "").equalsIgnoreCase(overrideURL.replaceAll("/+$", ""));
    }

    static AzureEnvironment resolveAzureEnv(String envName) {
        AzureEnvironment env;
        if (Constants.ENV_AZURE.equalsIgnoreCase(envName)) {
            env = AzureEnvironment.AZURE;
        } else if (Constants.ENV_AZURE_CHINA.equalsIgnoreCase(envName)) {
            env = AzureEnvironment.AZURE_CHINA;
        } else if (Constants.ENV_AZURE_GERMANY.equalsIgnoreCase(envName)) {
            env = AzureEnvironment.AZURE_GERMANY;
        } else if (Constants.ENV_AZURE_US_GOVERNMENT.equalsIgnoreCase(envName)) {
            env = AzureEnvironment.AZURE_US_GOVERNMENT;
        } else {
            env = AzureEnvironment.AZURE;
        }

        // The AzureEnvironment#endpoints() method is exposing the internal endpoint map, which means the call site
        // may change the details of the built-in known environments.
        // The ideal fix should be applied in Azure SDK. Here we make a copy so that other plugins that calls this
        // method won't modify the known environments by accident.
        return new AzureEnvironment(new HashMap<>(env.endpoints()));
    }

    public static class Constants {
        static final String ENV_AZURE = "Azure";
        static final String ENV_AZURE_CHINA = "Azure China";
        static final String ENV_AZURE_GERMANY = "Azure Germany";
        static final String ENV_AZURE_US_GOVERNMENT = "Azure US Government";
    }

    private AzureEnvUtil() {

    }
}
