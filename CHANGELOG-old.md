# Azure Credentials Plugin Changelog

See [GitHub releases](https://github.com/jenkinsci/azure-credentials-plugin/releases) for all newer versions.

## Version 4.0.6, 2021-02-20
* Update document 

## Version 4.0.5, 2020-12-02
* Added proxy support

## Version 4.0.4, 2020-12-02
* Move document to GitHub

## Version 4.0.3, 2020-10-26
* Update maintainer

## Version 4.0.2, 2020-04-26
NOTES:
* Please ignore v3.0.1, v4.0.0, v4.0.1. These versions are not compatible with other Azure-plugins.

BUG FIXES:
* Fix compatibility issue with other azure-plugins.

## Version 4.0.1, 2020-04-24
* Update ```compatibleSinceVersion``` to v4.0.0

## Version 4.0.0, 2020-04-23
* Encrypt subscriptionId, tenant, clientId. SubscriptionId, tenant, clientId will be returned as ```Secret``` type.

## Version 3.0.1, 2020-04-21
* Encrypt Service Principal subscriptionId, tenant, clientId 

## Version 3.0.0, 2020-03-30
* Upgrade Azure-SDK dependency to Azure-security-keyvault-secrets
* Fix compatibility issue with azure-keyvault
* Remove UsernamePassword support in Azure Key Vault
* Remove UsernamePassword support in ```AzureClient``` creation

## Version 2.0.2, 2020-03-24
* Upgrade Azure SDK dependency to version 1.31.0

## Version 2.0.1, 2020-01-25
* Fix service principal secret for key vault credential

## Version 2.0.0, 2020-01-23
* Bump Jenkins version to 2.60.3
* Support retrieving key vault items with more credentials type

## Version 1.6.1, 2019-03-29
* Support managed identities for Azure resources

## Version 1.6.0, 2018-03-29
* Use scoped credentials lookup

## Version 1.5.0, 2018-02-09
* Support for certificate based service principal
* Fix the configuration verification bug on non-global clouds

## Version 1.4.0, 2017-12-21
* Support Environment selection for MSI credentials

## Version 1.3.1, 2017-11-27
* Disable plugin first class loader to fix remote class loading issue before Jenkins 2.66.
   `PluginFirstClassLoader#findResource` returns null which causes `ClassNotFoundException` on remote class loading from slave to master.

## Version 1.3, 2017-11-03
* Support for Azure KeyVault credentials
* Support for MSI credentials
* Upgrade Azure SDK dependency to version 1.3.0
* Add Third Party Notices

## Version 1.2, 2017-06-19
* Show unencrypted value for subscription ID, client ID and OAuth2 endpoint in credentials update page
* Custom binding for Azure credentials

## Version 1.1, 2017-06-02
* Fix tenant field in credentials update page

## Version 1.0, 2017-03-08
* Initial release with support to Azure Service Principal credentials
