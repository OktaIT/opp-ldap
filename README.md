# opp-ldap
Okta OPP (On Premises Provisioning) connector to LDAP.

This connector simply takes a SCIMResource object from Okta and uses the mappings defined in connector.properties to build an DN and attributes to insert into a LDAP server. Check out the wiki to learn how it works and how to install it.

## Background on OPP
* [On Premises Provisioning Deployment Guide](https://support.okta.com/articles/Knowledge_Article/46749316-On-Premises-Provisioning-Deployment-Guide)
* ["From Legacy Software to Modern Identity Management Service"](https://www.okta.com/solutions/replacing-legacy-identity-software.html)
* [Okta Delivers New Services That Open and Extend its Enterprise Identity Network to Connect Every Application, Device and Person Across Enterprises](https://www.okta.com/company/pr-2013-11-04.html) - November 4th, 2013

## Disclaimer & License
Please be aware that all material published under the [OktaIT](https://github.com/OktaIT/) project have been written by the [Okta](http://www.okta.com/) IT Department but are **NOT OFFICAL** software release of Okta Inc.  As such, the software is provided "as is" without warranty or customer support of any kind.

This project is licensed under the MIT license, for more details please see the LICENSE file.
