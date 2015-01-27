# opp-ldap
Okta OPP (On Premises Provisioning) connector to LDAP

## Background on OPP
* [On Premises Provisioning Deployment Guide](https://support.okta.com/articles/Knowledge_Article/46749316-On-Premises-Provisioning-Deployment-Guide)
* ["From Legacy Software to Modern Identity Management Service"](https://www.okta.com/solutions/replacing-legacy-identity-software.html)
* [Okta Delivers New Services That Open and Extend its Enterprise Identity Network to Connect Every Application, Device and Person Across Enterprises](https://www.okta.com/company/pr-2013-11-04.html) - November 4th, 2013

## Setup
### LDAP
You can use whatever implementation of the LDAP you want. This connector was developed using OpenLDAP, but as long as the connector is configured properly, everything should work. More on the configuration later.
### OPA
1. Download the Okta Provisioning Agent installer from Settings->Downloads section of your Admin panel.
2. Installation instructions (detailed): a. https://support.okta.com/entries/29448976-Configuring-On-Premises-Provisioning#InstallingOPP
3. Installation instructions (brief)
	- sudo yum localinstall OktaProvisioningAgent-01.00.01.x86_64.rpm
	- /opt/OktaProvisioningAgent/configure_agent.sh
	- Enter subdomain
		- If connecting to a production Okta org, enter subdomain (ie: myorg) ii. If connecting to preview, enter full URL (ie: https://myorg.oktapreview.com)
	- service OktaProvisioningAgent start
	- service OktaProvisioningAgent status
	- If the service errors out with message “dead but subsys locked", remove the lock file
		- cd /var/lock/subsys
		- rm OktaProvisioningAgent
		- Then restart the service and check again
	- To make the OktaProvisioningAgent a service that starts on boot:
		- Get name of service’s script from /etc/init.d/ directory (ie: OktaProvisioningAgent)
		- Add it to chkconfig
			- sudo chkconfig --add OktaProvisioningAgent
		- Make sure it is in the chkconfig.
			- sudo chkconfig --list OktaProvisioningAgent
		- Set it to autostart
			- sudo chkconfig OktaProvisioningAgent on
		- To stop a service from auto starting on boot
			- sudo chkconfig OktaProvisioningAgent off
4. Log files are located in /opt/OktaProvisioningAgent/logs
### Connector
### Okta side

## Disclaimer & License
Please be aware that all material published under the [OktaIT](https://github.com/OktaIT/) project have been written by the [Okta](http://www.okta.com/) IT Department but are **NOT OFFICAL** software release of Okta Inc.  As such, the software is provided "as is" without warranty or customer support of any kind.

This project is licensed under the MIT license, for more details please see the LICENSE file.
