# Azure Credentials plugin

Jenkins plugin to manage Azure credentials.

* [General information on how to use credentials in Jenkins](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin)

It supports the following Azure credential types:

1. [Azure Service Principal](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal),
   with the following authentication mechanism:
   * Client secret
   * Certificate (Add the certificate to Jenkins credentials store and reference it in the Azure Service Principal configuration)
1. [Azure Managed Service Identity (MSI)](https://docs.microsoft.com/en-us/azure/active-directory/msi-overview)
1. [Credentials In Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started)

## Using Azure credentials in your own Jenkins plugin

1. Update your project POM file to reference `azure-credentials` plugin and necessary dependencies:

   ```xml
   ...
   <dependencies>
      <dependency>
          <groupId>org.jenkins-ci.plugins</groupId>
          <artifactId>azure-credentials</artifactId>
          <version>${azure-credentials.version}</version>
      </dependency>
      <dependency>
          <groupId>org.jenkins-ci.plugins</groupId>
          <artifactId>azure-commons-core</artifactId>
          <version>${azure-commons.version}</version>
      </dependency>
      ...
   </dependencies>
   <build>
      <plugins>
          <plugin>
              <groupId>org.jenkins-ci.tools</groupId>
              <artifactId>maven-hpi-plugin</artifactId>
              <configuration>
                  <maskClasses>
                      com.microsoft.jenkins.azurecommons.core.
                  </maskClasses>
               </configuration>
          </plugin>
       </plugins>
       ...
   </build>
   ```

1. Add the credential selector in the `config.jelly` and `Descriptor`
   ```Xml
    ...
    <f:entry title="${%azureCredentialsId_title}" field="azureCredentialsId">
        <c:select expressionAllowed="false"/>
    </f:entry>
    ...
   ```
   ```Java
    public ListBoxModel doFillAzureCredentialsIdItems(@AncestorInPath Item owner) {
        StandardListBoxModel model = new StandardListBoxModel();
        model.add(Messages.ACSDeploymentContext_selectAzureCredentials(), Constants.INVALID_OPTION);
        model.includeAs(ACL.SYSTEM, owner, AzureBaseCredentials.class);
        return model;
    }
   ```

1. Build the Azure client from the credential

   ```Java
   AzureBaseCredentials credential = AzureCredentialUtil.getCredential2(credentialsId);
   // Resolve the class loader incompatibility issue. Works along with maskClasses in the POM
   TokenCredentialData token = TokenCredentialData.deserialize(credential.serializeToTokenData());
   Azure azClient = AzureClientFactory.getClient(token);
   ```

## Getting an iterator to all SYSTEM owned Azure Credentials

```Java
CredentialsProvider.lookupCredentials(AzureBaseCredentials.class, null, ACL.SYSTEM, Collections.<DomainRequirement>emptyList());
```

## Using AzureCredentials in the job (freestyle / pipeline)

Custom binding for AzureCredentials to support reading Azure service principal in both freestyle and pipeline using Credentials Binding plugin. 

In freestyle jobs, click `Use secret text(s) or file(s)` in the `Build Environment` in the configuration page and add a `Microsoft Azure Service Principal` item, which allows you add credential bindings where the *Variable* value will be used as the name of the environment variable that your build can use to access the value of the credential. With the default variable names you can reference the service principal as the following:

```bash
echo "My client id is $AZURE_CLIENT_ID"
echo "My client secret is $AZURE_CLIENT_SECRET"
echo "My tenant id is $AZURE_TENANT_ID"
echo "My subscription id is $AZURE_SUBSCRIPTION_ID"
```

In pipelines, there're two ways to construct this binding:

1.  With defaults, which will read specified service principal into four predefined environment variables: `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`. Sample pipeline code:

    ```groovy
    withCredentials([azureServicePrincipal('credentials_id')]) {
        sh 'az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET -t $AZURE_TENANT_ID'
    }
    ```

2.  With custom name, where you can control the names of the variables. Sample pipeline code:

    ```groovy
    withCredentials([azureServicePrincipal(credentialsId: 'credentials_id',
                                        subscriptionIdVariable: 'SUBS_ID',
                                        clientIdVariable: 'CLIENT_ID',
                                        clientSecretVariable: 'CLIENT_SECRET',
                                        tenantIdVariable: 'TENANT_ID')]) {
        sh 'az login --service-principal -u $CLIENT_ID -p $CLIENT_SECRET -t $TENANT_ID'
    }
    ```
