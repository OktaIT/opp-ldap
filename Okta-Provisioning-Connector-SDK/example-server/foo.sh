#!/bin/bash
> /home/kevin/apache-tomcat-7.0.57/bin/logs/scim-server-example.log
mvn package
cp -fv target/scim-server-example-01.02.00-SNAPSHOT.war /home/kevin/apache-tomcat-7.0.57/webapps/
vim /home/kevin/apache-tomcat-7.0.57/bin/logs/scim-server-example.log
