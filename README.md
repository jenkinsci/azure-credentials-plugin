# Azure Credentials plugin

Jenkins plugin to manage Azure credentials.

* [General information on how to use credentials in Jenkins](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin)

It supports the following Azure credential types:

1. [Azure Service Principal](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal),
   with the following authentication mechanism:
   * Client secret
   * Certificate (Add the certificate to Jenkins credentials store and reference it in the Azure Service Principal
      configuration)
1. [Azure Managed Service Identity (MSI)](https://docs.microsoft.com/en-us/azure/active-directory/msi-overview)
1. [Credentials In Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started)

## Using existing credentials to login to Azure using the Java Azure SDK

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
