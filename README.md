# Azure Credentials plugin

> ***Important***: This plug-in is maintained by the Jenkins community and won’t be supported by Microsoft as of February 29, 2024.

## About this plugin

Jenkins plugin to manage Azure credentials.

* [General information on how to use credentials in Jenkins](https://plugins.jenkins.io/credentials/)

It supports the following Azure credential types:

1. [Azure Service Principal](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal),
   with the following authentication mechanism:
    * Client secret
    * Certificate (Add the certificate to Jenkins credentials store and reference it in the Azure Service Principal configuration)
1. [Azure Managed Identity (MSI)](https://docs.microsoft.com/en-us/azure/active-directory/msi-overview)
1. Basic support for [credentials In Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started),
for full support please use the [Azure Key Vault plugin](https://plugins.jenkins.io/azure-keyvault/).

## Using AzureCredentials in a job (freestyle / pipeline)

### Freestyle

In freestyle jobs, click `Use secret text(s) or file(s)` in the `Build Environment` in the configuration page and 
add a `Azure Service Principal` item, which allows you to add credential bindings
where the *Variable* value will be used as the name of the environment variable
that your build can use to access the value of the credential.

With the default variable names you can reference the service principal as the following:

```bash
echo "My client id is $AZURE_CLIENT_ID"
echo "My client secret is $AZURE_CLIENT_SECRET"
echo "My tenant id is $AZURE_TENANT_ID"
echo "My subscription id is $AZURE_SUBSCRIPTION_ID"
```

### Scripted pipeline

In scripted pipelines, there are two ways to construct this binding:

1.  With defaults, which will read specified service principal into four predefined environment variables: 
    `AZURE_SUBSCRIPTION_ID`,
    `AZURE_CLIENT_ID`,
    `AZURE_CLIENT_SECRET`,
    `AZURE_TENANT_ID`.
    
Sample pipeline code:

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

### Declarative pipeline

In declarative pipeline it will add extra environment variables based off of the variable name you requested.

If you did `MY_CRED = credentials('credentials_id')`

You will get:
- `MY_CRED_CLIENT_ID`
- `MY_CRED_CLIENT_SECRET`
- `MY_CRED_TENANT_ID`
- `MY_CRED_SUBSCRIPTION_ID`

```groovy

pipeline {
  environment {
    MY_CRED = credentials('credentials_id')
  }

  stages {
    stage('build') {
      steps {
          sh 'az login --service-principal -u $MY_CRED_CLIENT_ID -p $MY_CRED_CLIENT_SECRET -t $MY_CRED_TENANT_ID'
      }
    }
  }
}

```

## Using Azure credentials in your own Jenkins plugin

1. Update your project POM file to reference `azure-credentials` plugin and necessary dependencies:

```xml
<dependencies>
   <dependency>
       <groupId>org.jenkins-ci.plugins</groupId>
       <artifactId>azure-credentials</artifactId>
       <version>${azure-credentials.version}</version>
   </dependency>
</dependencies>
```

1. Add the credential selector in the `config.jelly` and `Descriptor`
```xml
 <f:entry title="${%Azure Credential}" field="credentialsId">
     <c:select expressionAllowed="false"/>
 </f:entry>
```
```java
public ListBoxModel doFillAzureCredentialsIdItems(@AncestorInPath Item owner) {
    StandardListBoxModel result = new StandardListBoxModel();
    result.add("--- Select Azure Credentials ---", "");

    if (owner == null) {
        if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
            return result;
        }
    } else {
        if (!owner.hasPermission(Item.EXTENDED_READ)
                && !owner.hasPermission(CredentialsProvider.USE_ITEM)) {
            return result;
        }
    }
    return result
            .includeEmptyValue()
            .includeMatchingAs(
                    ACL.SYSTEM,
                    owner,
                    AzureBaseCredentials.class,
                    Collections.emptyList(),
                    CredentialsMatchers.instanceOf(
                            AzureBaseCredentials.class));
}
```

1. Build the Azure client from the credential

```java
public AzureResourceManager getResourceManager(String credentialId) {
    // Pass an Item instead of null if you're in a job/run context
   AzureBaseCredentials credential = AzureCredentialUtil.getCredential(null, credentialId);
   AzureProfile profile = new AzureProfile(azureCredentials.getAzureEnvironment());
   TokenCredential tokenCredential = AzureCredentials.getTokenCredential(azureCredentials);

   return AzureResourceManager
           .configure()
           .withHttpClient(HttpClientRetriever.get())
           .authenticate(tokenCredential, profile)
           .withSubscription(subscriptionId);
}
```

## Getting an iterator to all SYSTEM owned Azure Credentials

```java
CredentialsProvider
        .lookupCredentials(
           AzureBaseCredentials.class,
           null,
           ACL.SYSTEM,
           Collections.emptyList()
        );
```
