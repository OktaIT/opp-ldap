Example SCIM Server Connector
========

This provides a working SCIM connector example where users and groups are kept in an in-memory identity store.


Setup
----------
1. locate the /lib/scim-server-sdk jar file from the SDK root directory
2. Install it locally: mvn install:install-file -Dfile=../lib/scim-server-sdk-01.02.00.jar -DgroupId=com.okta.scim.sdk -DartifactId=scim-server-sdk -Dpackaging=jar -Dversion=01.02.00
3. Build the example: mvn package
4. Take the target/scim-server-example-*.war and copy it to your Tomcat directory and run it.
5. You can now use the tester to run methods against this example SCIM connector.


How To Enable SSL
------------------
If you follow the instructions in the Setup section above, you would have an integration between Okta and the SCIM Server you setup
using the SDK over Http (Plain text). Supporting SSL for Https connections would involve
a) Generating a key for the SCIM Server and exporting a certificate.
b) Importing the certificate exported above into the trust store of the Okta Provisioning Agent.

You can follow the simple steps below to enable SSL using self-signed certificates. If you wish to have better security
and use certificates signed by trusted third-parties, you can follow the last step (5) below to import such a certificate
into the trust store of the Okta Provisioning Agent.

1. Generate a key -

    keytool -genkey -alias scim_tom -keyalg RSA -keystore /root/scim_tomcat_keystore
    Enter keystore password:
    Re-enter new password:
    What is your first and last name?
      [Unknown]:  localhost
    What is the name of your organizational unit?
      [Unknown]:  IT
    What is the name of your organization?
      [Unknown]:  MyCompany
    What is the name of your City or Locality?
      [Unknown]:  sf
    What is the name of your State or Province?
      [Unknown]:  ca
    What is the two-letter country code for this unit?
      [Unknown]:  us
    Is CN=K0208, OU=eng, O=okta, L=sf, ST=ca, C=us correct?
      [no]:  yes

    Enter key password for <scim_tom>
    (RETURN if same as keystore password):

NOTE : The answer to the first question "What is your first and last name?" should be
       "localhost" if your Tomcat server is going to be accessed through the localhost URL.
       If your Tomcat Server will be accessed through an IP (For example : https://10.11.12.13:8443/), you should execute the
       following command in the place of the above command to generate the key.
       (Note that the command below should be executed from a Java 7 installation. The option "-ext san" to specify IPs in the SubjectAltNames
       is available only in Java 7)
       $JAVA_7_HOME/bin/keytool -genkey -alias scim_tom -ext san=ip:10.11.12.13 -keyalg RSA -keystore /root/scim_tomcat_keystore

2. Go to $TOMCAT_HOME/conf/server.xml and enable SSL - Use the configuration below which asks Tomcat
to use the keystore /root/scim_tomcat_keystore (Generated above)
    <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
               maxThreads="150" scheme="https" secure="true"
               clientAuth="false" sslProtocol="TLS"
               keystoreFile="/root/scim_tomcat_keystore"
               keystorePass="changeit" />
3. Start tomcat and check you can reach the server over https
4. Export the public certificate out of the keystore generated in step 1 -
   keytool -export -keystore /root/scim_tomcat_keystore -alias scim_tom -file /root/scim_tomcat.cert
   Enter keystore password:
   Certificate stored in file </root/scim_tomcat.cert>
5. Import this certificate into the trust store of the Okta Provisioning Agent so that it can trust
Tomcat server and the connection is secure. Note that you need to execute this command on the machine
where the Okta Provisioning Agent is installed -
    /opt/OktaProvisioningAgent/jre/bin/keytool -import -file /root/scim_tomcat.cert -alias scim_tom -keystore /opt/OktaProvisioningAgent/jre/lib/security/cacerts

Use Files To Store Users/Groups
-------------------------------
The example server stores users/groups in memory. If you want to create users/groups in the example server, you should edit the code in SCIMServerImpl class.
If you want to create users/groups in the example server without changing the code, you can specify the absolute paths for the files to read from/store into. They should be
specified as values for the properties usersFilePath and groupsFilePath in dispatcher-servlet.xml.
The SDK ships with sample users.json and groups.json (Located at scim-server-example/src/main/resources/data). You can specify the complete path for these files in dispatcher-servlet.xml.

Whenever new users/groups/updates are pushed from Okta into the example server, these files will be updated.
If you want to edit these files manually so that the users/groups in the edited file are imported into Okta, you should restart tomcat after editing these files.
