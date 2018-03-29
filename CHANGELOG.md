# Azure Credentials Plugin Changelog

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
