# opp-ldap
Okta OPP (On Premises Provisioning) connector to LDAP

## Background on OPP
* [On Premises Provisioning Deployment Guide](https://support.okta.com/articles/Knowledge_Article/46749316-On-Premises-Provisioning-Deployment-Guide)
* ["From Legacy Software to Modern Identity Management Service"](https://www.okta.com/solutions/replacing-legacy-identity-software.html)
* [Okta Delivers New Services That Open and Extend its Enterprise Identity Network to Connect Every Application, Device and Person Across Enterprises](https://www.okta.com/company/pr-2013-11-04.html) - November 4th, 2013

## Setup
Big Thanks to ayee@okta.com for writing most of the setup documentation.
This is just a quick setup guide. The testing environment was on CentOS. More thorough instructions can be found:

Installing and Configuring  the OPA:
- https://support.okta.com/entries/29448976-Configuring-On-Premises-Provisioning#installing

More info:
- https://support.okta.com/entries/46749316-On-Premises-Provisioning-Deployment-Guide

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
During development, the connector was hosted on Tomcat and used Maven to build the war. So those two packages (and Java) will need to be installed,

####Install Java (required to install Tomcat and Maven)
1. Install
	- sudo yum install java-1.7.0-openjdk-devel
2. Set the JAVA_HOME environment variable (required for Apache Maven)
	- Determine the correct value for JAVA_HOME. CentOS installs OpenJDK 1.7 into either /usr/lib/jvm/java-1.7.0-openjdk-1.7.0.0/ or /usr/lib/jvm/java-1.7.0-openjdk-1.7.0.0.x86_64/, depending on whether your system is a 32-bit or 64-bit architecture. The JAVA_HOME should point to the directory containing a bin/java executable.
	- As the user who will use OpenJDK, open the shell configuration file. For the Bash shell, this file is /home/username/.bashrc.
	- At the bottom of the file, type the following line, replacing the hypothetical path with the actual path to use on your own system: export JAVA_HOME="/path/to/java/home"
	- Save the file, and log out of and back into your session.

####Install Tomcat (default location: /usr/share/tomcat6)
1. Run to install:
	- sudo yum install tomcat6 tomcat6-webapps tomcat6-admin-webapps
2. Configure Tomcat to start as a service
	- sudo chkconfig tomcat6 on
3. Start service
	- sudo service tomcat6 start

####Install Maven (default location: /usr/local/apache-maven-3.1.1)
1. wget http://mirror.cc.columbia.edu/pub/software/apache/maven/maven-3/3.1.1/binaries/apache-maven-3.1.1-bin.tar.gz
2. sudo tar xzf apache-maven-3.1.1-bin.tar.gz -C /usr/local
3. cd /usr/local
4. Set the following environment variables (add lines to the user’s profile in .bashrc)
- export M2_HOME="/usr/local/apache-maven-3.1.1"
- export M2=$M2_HOME/bin
- export PATH=$M2:$PATH
5. Log out and log back in
6. Test Maven install by viewing environment variables:
- mvn -version

### Okta side

## Disclaimer & License
Please be aware that all material published under the [OktaIT](https://github.com/OktaIT/) project have been written by the [Okta](http://www.okta.com/) IT Department but are **NOT OFFICAL** software release of Okta Inc.  As such, the software is provided "as is" without warranty or customer support of any kind.

This project is licensed under the MIT license, for more details please see the LICENSE file.
