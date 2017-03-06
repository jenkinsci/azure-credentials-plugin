# Azure Credentials plugin

Jenkins Plugin to manage Azure Service Principal credentials.

* [Bash Script for creating a service principal](https://github.com/Azure/azure-devops-utils/blob/master/bash/create-service-principal.sh)
* [General information on how to use credentials in Jenkins](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin)

#### Using existing credentials to login to Azure using the Java Azure SDK
```Java
ServicePrincipal servicePrincipal = AzureCredentials.getServicePrincipal("<credentials_id>");
Azure azClient = Azure.authenticate(new ApplicationTokenCredentials(
                servicePrincipal.getClientId(),
                servicePrincipal.getTenant(),
                servicePrincipal.getClientSecret(),
                new AzureEnvironment(
                        servicePrincipal.getAuthenticationEndpoint(),
                        servicePrincipal.getServiceManagementURL(),
                        servicePrincipal.getResourceManagerEndpoint(),
                        servicePrincipal.getGraphEndpoint()
                ));
```

#### Getting an iterator to all SYSTEM owned Azure Credentials
```Java
CredentialsProvider.lookupCredentials(AzureCredentials.class, null, ACL.SYSTEM, Collections.<DomainRequirement>emptyList()
```