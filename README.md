# opp-ldap
Okta OPP (On Premises Provisioning) connector to LDAP. Big Thanks to ayee@okta.com for writing most of the setup documentation.

## Background on OPP
* [On Premises Provisioning Deployment Guide](https://support.okta.com/articles/Knowledge_Article/46749316-On-Premises-Provisioning-Deployment-Guide)
* ["From Legacy Software to Modern Identity Management Service"](https://www.okta.com/solutions/replacing-legacy-identity-software.html)
* [Okta Delivers New Services That Open and Extend its Enterprise Identity Network to Connect Every Application, Device and Person Across Enterprises](https://www.okta.com/company/pr-2013-11-04.html) - November 4th, 2013

## Setup
This is just a quick setup guide. The testing environment was on CentOS and RHEL. More thorough instructions can be found:

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

####Install Okta Provisioning Connector SDK
1. Download the Okta Provisioning Connector SDK
	- Login to Okta as an admin
	- Find the file at Settings > Downloads > Admin Downloads
2. Extract to /opt/Okta-Provisioning-Connector-SDK/
	- Going forward, this will be called the <SDK root directory>
3. Grant read/write permissions to /opt to your user if you’re building the example connector as a non root user

####Build Example Connector
1. cd to <SDK root directory>/lib where the scim-server-sdk.jar file is
2. Install it locally
	- mvn install:install-file -Dfile=../lib/scim-server-sdk-01.02.00.jar -DgroupId=com.okta.scim.sdk -DartifactId=scim-server-sdk -Dpackaging=jar -Dversion=01.02.00
	- Note: the command above is for SDK version 01.02.00; modify as necessary
3. Build the LDAP connector
	- Note: you must be in the same directory as the pom.xml file
		- cd to <SDK root directory>/example-mysql-server/
	- Note: you must run mvn package as the same user who installed the SDK (step 2)
	- mvn package

####Deploy Example Connector
- Copy the target/scim-server-example-01.02.00-SNAPSHOT.war to your Tomcat webapps directory.
- cp /opt/Okta-Provisioning-Connector-SDK/example-server-mysql-server/target/scim-server-example-01.02.00-SNAPSHOT.war /usr/share/tomcat6/webapps
- Note: the command above is for SDK version 01.02.00; modify as necessary.

####Verify Successful Deployment of Connector
1. Navigate to http://localhost:8080/manager/html and login
	- This assumes you’ve setup a user with the “manager” role in the conf/tomcat-user.xml file
	- ie: <user username="tomcat" password="s3cret" roles="manager"/>
2. Find the SCIM connector app and verify that it is running (look for “true” in the Running column)
3. If it did not start, view the Tomcat log files under /usr/share/tomcat6/logs
	- scim-mysql-connector-example.log

### Okta side
####Connect to Okta Service and Test
1. Login to Okta as an admin and either create or navigate to your app named “onprem_app”
2. General tab > select “Enable on-premises user management configuration”
3. Provisioning tab appears
4. Navigate to the Provisioning tab and configure the following:
	- SCIM Connector base URL: http://localhost:8080/scim-mysql-connector-example-01.01.00-SNAPSHOT
		- Note: the info above is for SDK version 01.01.00; modify as necessary
	- Authorization type: None
	- Unique user field name: userName
	- Connect to these agents: select the agent you installed
5. Click Test Connector Configuration
	- Should show success and the functions that are supported
7. Assign the application to a user or a group
	- Check whether the user was created
8. Check the agent.log under OPA/logs folder to see command activity from the Okta service

###Other Notes:
####Enabling Basic Auth
1. Add the role and user to your tomcat-users.xml file, which was located /usr/share/tomcat/conf/ in my testing environment.
	- Note: the connector was configured to user the rolename "member", you can edit this in opp-ldap/Okta-Provisioning-Connector-SDK/example-server/src/main/webapp/WEB-INF/web.xml
```XML
		<role rolename="member"/>
		<user username="scim" password="test" roles="member" />
```
2. In the provisioning tab of the app, select Basic Auth for the Authorization type and enter the Basic Auth credentials.

####Enabling HTTPS
More detailed instructions can be found opp-ldap/Okta-Provisioning-Connector-SDK/example-server/README.txt.
- Note: This will only outline how to enable HTTPS with a self signed cert.If you wish to have better security
and use certificates signed by trusted third-parties, you can follow the last step (5) below to import such a certificate
into the trust store of the Okta Provisioning Agent.
1. Generate a key.
```Shell
	keytool -genkey -alias scim_tom -keyalg RSA -keystore /root/scim_tomcat_keystore
```
	- Note: Be mindful of where you store your keystore, the tomcat user needs to be able to see the keystore.
2. Go to $TOMCAT_HOME/conf/server.xml and enable SSL - Use the configuration below which asks Tomcat
to use the keystore /root/scim_tomcat_keystore (Generated above)
```XML
	<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
		maxThreads="150" scheme="https" secure="true"
		clientAuth="false" sslProtocol="TLS"
		keystoreFile="/root/scim_tomcat_keystore"
		keystorePass="changeit" />
```
3. Start tomcat and check you can reach the server over https
4. Export the public certificate out of the keystore generated in step 1 -
```Shell
	keytool -export -keystore /root/scim_tomcat_keystore -alias scim_tom -file /root/scim_tomcat.cert
```
5. Import this certificate into the trust store of the Okta Provisioning Agent so that it can trust Tomcat server and the connection is secure. Note that you need to execute this command on the machine where the Okta Provisioning Agent is installed -
```Shell
    /opt/OktaProvisioningAgent/jre/bin/keytool -import -file /root/scim_tomcat.cert -alias scim_tom -keystore /opt/OktaProvisioningAgent/jre/lib/security/cacerts
```
	- Note: the password for cacerts is "changeit", remember to change this.

## Disclaimer & License
Please be aware that all material published under the [OktaIT](https://github.com/OktaIT/) project have been written by the [Okta](http://www.okta.com/) IT Department but are **NOT OFFICAL** software release of Okta Inc.  As such, the software is provided "as is" without warranty or customer support of any kind.

This project is licensed under the MIT license, for more details please see the LICENSE file.
