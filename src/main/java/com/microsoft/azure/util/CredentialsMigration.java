package com.microsoft.azure.util;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.microsoft.azure.AzureEnvironment;
import hudson.security.ACL;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Migrate credentials used by Azure SDK before version 1.1.0.
 */
public final class CredentialsMigration {
    private static final Logger LOGGER = Logger.getLogger(CredentialsMigration.class.getName());

    private static final String CREDENTIALS_FILE = "credentials.xml";

    private static Map<String, AzureCredentials> convertAzureCredentials(final File inputFile)
            throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();

        Document document = builder.parse(inputFile);

        Map<String, AzureCredentials> credentials = new HashMap<>();

        NodeList nodeList = document.getElementsByTagName("com.microsoft.azure.util.AzureCredentials");
        for (int i = 0; i < nodeList.getLength(); ++i) {
            Node node = nodeList.item(i);

            if (node.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }

            Element elem = (Element) node;

            // we've already done the migration
            if (StringUtils.isNoneBlank(getNodeValue(elem, "azureSDKVersion"))) {
                return credentials;
            }

            CredentialsScope scope = CredentialsScope.valueOf(getNodeValue(elem, "scope"));
            String id = getNodeValue(elem, "id");
            String description = getNodeValue(elem, "description");

            String subscriptionId = getNodeValue(elem, "data.subscriptionId", true);
            String clientId = getNodeValue(elem, "data.clientId", true);
            String clientSecret = getNodeValue(elem, "data.clientSecret", true);
            String tenant = AzureCredentials.ServicePrincipal.getTenantFromTokenEndpoint(
                    getNodeValue(elem, "data.oauth2TokenEndpoint", true));
            String managementEndpointUrl = getNodeValue(elem, "data.serviceManagementURL");
            String activeDirectoryEndpointUrl = getNodeValue(elem, "data.authenticationEndpoint");
            String resourceManagerEndpointUrl = getNodeValue(elem, "data.resourceManagerEndpoint");
            String graphEndpointUrl = getNodeValue(elem, "data.graphEndpoint");

            String environmentStr = resolveEnvironment(
                    managementEndpointUrl,
                    activeDirectoryEndpointUrl,
                    resourceManagerEndpointUrl,
                    graphEndpointUrl);
            if (environmentStr != null) {
                managementEndpointUrl = "";
                activeDirectoryEndpointUrl = "";
                resourceManagerEndpointUrl = "";
                graphEndpointUrl = "";
            } else {
                environmentStr = AzureCredentials.DEFAULT_ENVIRONMENT;
            }

            AzureCredentials credential = new AzureCredentials(
                    scope,
                    id,
                    description,
                    subscriptionId,
                    clientId,
                    clientSecret,
                    tenant,
                    environmentStr,
                    managementEndpointUrl,
                    activeDirectoryEndpointUrl,
                    resourceManagerEndpointUrl,
                    graphEndpointUrl);
            credentials.put(credential.getId(), credential);
        }

        return credentials;
    }

    public static void upgradeAzureCredentialsConfig() throws Exception {
        File sourceFile = new File(getWorkDirectory(), CREDENTIALS_FILE);

        try {
            Map<String, AzureCredentials> credentials = convertAzureCredentials(sourceFile);
            if (credentials.isEmpty()) {
                // either no credentials found, or we have already done the conversion.
                return;
            }

            List<AzureCredentials> legacyCredentials = CredentialsProvider.lookupCredentials(
                    AzureCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.<DomainRequirement>emptyList());

            final SecurityContext securityContext = ACL.impersonate(ACL.SYSTEM);
            try {
                Iterable<CredentialsStore> stores = CredentialsProvider.lookupStores(Jenkins.getInstance());
                for (CredentialsStore store : stores) {
                    for (AzureCredentials legacyCredential : legacyCredentials) {
                        final String id = legacyCredential.getId();
                        final AzureCredentials updated = credentials.get(id);
                        if (updated != null) {
                            boolean ret = store.updateCredentials(Domain.global(), legacyCredential, updated);
                            if (ret) {
                                LOGGER.log(Level.INFO, "Migrated AzureCredentials " + id);
                            }
                        } else {
                            LOGGER.log(Level.SEVERE, "Migration for AzureCredentials " + id + " was not found");
                        }
                    }
                }
            } finally {
                SecurityContextHolder.setContext(securityContext);
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Exception found while migrating AzureCredentials: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * In the earlier version (1.1), the AzureEnvironment is provided by constructing a new instance with the four
     * URL's filled from the credentials configuration form.
     *
     * In the migration, we check if the four URL's match any of the existing environments. If yes, we return that
     * environment and clear all the overrides. Otherwise, we choose Azure global as the default environment, and
     * apply the URL's from earlier version as explicit overrides.
     */
    private static String resolveEnvironment(
            final String managementEndpointUrl,
            final String activeDirectoryEndpointUrl,
            final String resourceManagerEndpointUrl,
            final String graphEndpointUrl) {
        for (Map.Entry<String, Pair<String, AzureEnvironment>> entry : AzureCredentials.ENVIRONMENT_MAP.entrySet()) {
            AzureEnvironment env = entry.getValue().getRight();
            if (sameUrl(env.managementEndpoint(), managementEndpointUrl)
                    && sameUrl(env.activeDirectoryEndpoint(), activeDirectoryEndpointUrl)
                    && sameUrl(env.resourceManagerEndpoint(), resourceManagerEndpointUrl)
                    && sameUrl(env.graphEndpoint(), graphEndpointUrl)) {
                return entry.getKey();
            }
        }
        return null;
    }

    private static boolean sameUrl(final String base, final String target) {
        if (StringUtils.isBlank(target)) {
            return false;
        }
        String enrichedBase = base;
        if (!base.endsWith("/")) {
            enrichedBase = base + '/';
        }
        String enrichedTarget = target;
        if (!target.endsWith("/")) {
            enrichedTarget = target + '/';
        }
        return enrichedBase.equals(enrichedTarget);
    }

    private static String getWorkDirectory() {
        File jenkinsRoot;
        jenkinsRoot = Jenkins.getInstance().root;
        if (jenkinsRoot == null) {
            throw new IllegalStateException("Root isn't configured. Couldn't find Jenkins work directory.");
        }

        return jenkinsRoot.getAbsolutePath();
    }

    private static String getNodeValue(final Element elem, final String path) {
        return getNodeValue(elem, path, false);
    }

    private static String getNodeValue(final Element elem, final String path, final boolean isSecret) {
        String[] parts = path.split("\\.");
        Element current = elem;
        for (int i = 0; current != null && i < parts.length; ++i) {
            NodeList list = current.getElementsByTagName(parts[i]);
            if (list.getLength() <= 0) {
                return "";
            }
            Node node = list.item(0);
            if (node.getNodeType() != Node.ELEMENT_NODE) {
                return "";
            }
            current = (Element) node;
        }
        String value = current.getChildNodes().item(0).getNodeValue();
        if (!isSecret) {
            return value;
        }
        Secret secret = Secret.fromString(value);
        return secret.getPlainText();
    }

    private CredentialsMigration() {
        // hide constructor
    }
}
