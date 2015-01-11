scim-sdk-tests
===

Overview
---------------
Allows you to test your SCIM connector methods individually and isolated from Okta and the Okta Provisioning Agent. When a test is successful the process exit code will be a 0, if there was an error the exit code will be a 1.
Each connector method test assumes that the input data is already valid, the tests main focus is to validate the response from your SCIM connector. Edit or create the sample data files carefully!
Each connector method prints out a different amount of information depending on the number of items returned and the amount of validation that can be done.

Capabilities Mappings
---------------
When implementing your connector and the SCIMService interface, you will tell Okta what UserManagementCapabilities you will implemented in your connector.
Those capabilities do not map 1 to 1 to the method names that we use below in our tester. But the following table will map those UserManagementCapabilities to the method names used for this tester.

    UserManagementCapabilities enum         SCIMService methods         tester methodName argument

    GROUP_PUSH                              deleteGroup                 deleteGroup
                                            updateGroup                 updateGroup
                                            createGroup                 createGroup
                                            getGroup                    getGroupById

    IMPORT_NEW_USERS                        getUsers                    downloadUsers
                                            getGroups                   downloadGroups

    IMPORT_PROFILE_UPDATES                  getUser                     importUserProfile

    PUSH_NEW_USERS                          createUser                  createNewUser
                                            getUsers                    checkUserExists

    PUSH_PASSWORD_UPDATES                   updateUser                  pushPasswordUpdate

    PUSH_PENDING_USERS                      createUser                  createPendingUser
                                            updateUser                  activateUser
                                            getUsers                    checkUserExists

    PUSH_PROFILE_UPDATES                    updateUser                  pushProfileUpdate

    PUSH_USER_DEACTIVATION                  updateUser                  deactivateUser

    REACTIVATE_USERS                        updateUser                  reactivateUser

    -                                       getImplementedUserManagementCapabilities


Usage
---------------
To see all possible arguments, run the jar without any arguments.
    java -jar scim-sdk-tests.jar

    usage: scim-sdk-tests
     -arg <propertyName=propertyValue>   Pass any property name & value pair for your method to use.

     -expectResults <true|false>         Set test expectations on if results should come back from the connector for the current method. This can be used with the following methods: checkUserExists,
                                         downloadUsers, downloadGroups, importUserProfile

     -file <fileName>                    The data file to use as input for the current method

     -header <headerName=headerValue>    Any additional HTTP header you want sent to the SCIM server. ex: X-Internal-AuthHeader=secret

     -method <methodName>                The Okta provisioning method to test:
                                         createNewUser - Okta will pass a User object to create a new user using your connector. Tests the connector method SCIMService.createUser
                                         createPendingUser - Okta will pass a User object to create a pending user using your connector. Tests the connector method SCIMService.createUser

                                         downloadUsers - Okta will ask your connector to return the full list of users. Tests the connector method SCIMService.getUsers (without a filter)
                                         checkUserExists - Okta will ask your connector if a specific user already exists. Requires the additional properties: userIdFieldName and userIdFieldValue. Tests
                                         the connector method SCIMService.getUsers (with a filter)

                                         importUserProfile - Okta will ask your connector to return a single user, passing it the user's id. Requires the additional property: id. Tests the
                                         connector method SCIMService.getUser

                                         activateUser - Okta will ask your connector to activate an existing user. Tests the connector method SCIMService.updateUser
                                         deactivateUser - Okta will ask your connector to deactivate an existing user. Tests the connector method SCIMService.updateUser
                                         reactivateUser - Okta will ask your connector to reactivate an existing user. Tests the connector method SCIMService.updateUser
                                         pushPasswordUpdate - Okta will ask your connector to update the password of an existing user. Tests the connector method SCIMService.updateUser
                                         pushProfileUpdate - Okta will ask your connector to update the properties of an existing user. Tests the connector method SCIMService.updateUser

                                         deleteGroup - Okta will ask your connector to delete a group. Tests the connector method SCIMService.deleteGroup

                                         updateGroup - Okta will ask your connector to update a group. Tests the connector method SCIMService.updateGroup

                                         createGroup - Okta will ask your connector to create a group. Tests the connector method SCIMService.createGroup

                                         getGroupById - Okta will ask your connector to return a group based on the id. Tests the connector method SCIMService.getGroup

                                         downloadGroups - Okta will ask your connector to return the full list of groups. Tests the connector method SCIMService.getGroups

                                         getImplementedUserManagementCapabilities - Okta will ask your connector to return the list of UserManagementCapabilities your connector has implemented. Tests the connector method SCIMService.getImplementedUserManagementCapabilities

     -url <url>                          The URL of the SCIM server to use. ex: http://localhost:8080/. NOTE: When accessing a server that uses Server Name Indication (SNI), you must run the tester using Java 7 or greater.


Common Arguments
---------------
    -url <url>
    The base url of the SCIM server should be supplied every time.

    -file <fileName>
    [Optional] path to the file that will be used as the argument to the connector method. Data files are not required for all connector methods.

    -header <headerName=headerValue>
    [Optional] An additional HTTP header and value to send with each SCIM request. If you need more headers you can pass multiple -header arguments.

    -expectResults <true|false>
    [Optional] Only valid for a certain set of connector methods. Sets the test expectation if the SCIM server will or will not return any users or groups.
    If -expectResults is true and the SCIM server returns users or groups that the test will be judged as a failure.
    if -expectResults is not supplied, true is the assumed default.

    -arg <propertyName=propertyValue>
    [Optional] Only required for a subset of connector methods. Allows you to supply additional test parameters for your test. You can pass multiple -arg arguments.


Examples
==========

The default implementation provided by Okta assumes that the appname to be "onprem_app" and the examples below and the input data files in the data folder use
the custom schema name (urn:okta:onprem_app:1.0:user) for the App User custom schemas. When you implement the connector you need to use the correct appname.

createNewUser
---------------
createNewUser will pass a SCIM User object in an attempt to create a new user using your connector, it tests the SCIMService.createUser connector SDK method. There are two supplied example data files to test with.

The test below will send the SCIM user defined in the createNewUser.json file to your SCIM connector. Some basic validation will be performed on the user returned from your connector.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method createNewUser -file data/createNewUser.json
    [ 04-10-2013 13:23:01.258 ] [  INFO] - making POST request to http://localhost:8080/Users
    [ 04-10-2013 13:23:01.449 ] [  INFO] - Okta will use the ID 103 to identify this User in the future.
    [ 04-10-2013 13:23:01.450 ] [  INFO] - User returned from connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0"
    phoneNumbers:
        value: "123-444-5555"
        type: "mobile"

    userName: "myemail@domain.com"
    name:
        familyName: "LastName"
        givenName: "FirstName"

    active: true
    emails:
        primary: true
        value: "myemail@domain.com"
        type: "primary"

        primary: false
        value: "mypersonalemail@domain.com"
        type: "secondary"

    password: "verySecure"
    id: "103"

    [ 04-10-2013 13:23:01.450 ] [  INFO] - OK!



createPendingUser
---------------
createPendingUser will pass a SCIM User object int an attempt to create a pending user using your connector, it tests the SCIMService.createUser connector SDK method. There are two supplied example data files to test with.
createPendingUser is almost identical to createNewUser except that the active field for all users will be false.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method createPendingUser -file data/createPendingUser-withCustomExtension.json



downloadUsers
---------------
downloadUsers will ask your connector to return the full list of users it tests the SCIMService.getUsers connector method without passing it a filter.

The test below will make a request to your SCIM connector asking for all users and the returned users will be logged to disk. The test could make multiple requests to your connector if multiple pages of users exist.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method downloadUsers
    [ 04-10-2013 14:14:18.888 ] [  INFO] - making GET request to http://localhost:8080/Users?startIndex=1&count=100
    [ 04-10-2013 14:14:19.003 ] [  INFO] - downloadUsers: 3 Users returned.
    [ 04-10-2013 14:14:19.007 ] [  INFO] - downloadUsers: Users returned from connector logged to downloadUsers-20131004-141419.txt



checkUserExists
---------------
checkUserExists will ask your connector if a specific user already exists, it tests the SCIMService.getUsers connector method by passing it a filter.
Requires the additional properties: userIdFieldName and userIdFieldValue. Has the optional additional properties: userIdFieldName2 and userIdFieldValue2.

The test below will use the supplied properties to make a request to your SCIM connector. The test assumes that your SCIM connector will not find a user with the userName myemail@domain.com.
The output should look similar to this:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=userName -arg userIdFieldValue=myemail@domain.com -expectResults false
    [ 03-10-2013 14:54:16.741 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=userName%20eq%20%22myemail%40domain.com%22&startIndex=1&count=100
    [ 03-10-2013 14:54:16.846 ] [  INFO] - checkUserExists: No users returned from server. This should be expected.
    [ 03-10-2013 14:54:16.846 ] [  INFO] - OK!

- - -
Running the below (leaving off the -expectResults argument) should cause the tests to fail:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=userName -arg userIdFieldValue=myemail@domain.com
    [ 03-10-2013 14:57:41.218 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=userName%20eq%20%22myemail%40domain.com%22&startIndex=1&count=100
    [ 03-10-2013 14:57:41.319 ] [ ERROR] - Expected results from checkUserExists but did not get anything.

- - -
When your connector has found a user the user data will be printed out, in addition to some additional Okta debugging information:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=id -arg userIdFieldValue=102
    [ 03-10-2013 15:01:14.095 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=id%20eq%20%22102%22&startIndex=1&count=100
    [ 03-10-2013 15:01:14.217 ] [  INFO] - checkUserExists: 1 users returned.
    [ 03-10-2013 15:01:14.217 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user"
    id: "102"
    userName: "admin"
    name:
        formatted: "Barbara Jensen"
        givenName: "Barbara"
        familyName: "Jensen"
        middleName: "Brian"

    emails:
        value: "bjensen@example.com"
        primary: true
        type: "work"

    active: false
    password: "god"
    groups:
        value: "1002"
        display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
        isAdmin: true
        isOkta: false
        departmentName: "Administration"

    [ 03-10-2013 15:01:14.217 ] [  INFO] - checkUserExists: The ID 102 will be used as the id for this user in Okta
    [ 03-10-2013 15:01:14.217 ] [  INFO] - checkUserExists: The user will be returned as INACTIVE
    [ 03-10-2013 15:01:14.218 ] [  INFO] - OK!

- - -
How to search for a user by first name (no users found):

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=name.givenName -arg userIdFieldValue="SCIM first"
    [ 20-06-2014 09:20:18.342 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=name.givenName+eq+%22SCIM+first%22&startIndex=1&count=100
    [ 20-06-2014 09:20:18.627 ] [ ERROR] - Expected results from checkUserExists but did not get anything.

How to search for a user by first name (1 user found):

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=name.givenName -arg userIdFieldValue="john"
    [ 20-06-2014 09:26:30.146 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=name.givenName+eq+%22john%22&startIndex=1&count=100
    [ 20-06-2014 09:26:30.443 ] [  INFO] - checkUserExists: 1 users returned.
    [ 20-06-2014 09:26:30.493 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user:custom"
    id: "101"
    userName: "okta"
    password: "inSecure"
    active: true
    name:
    	formatted: "John Smith"
    	givenName: "John"
    	familyName: "Smith"

    emails:
    	value: "jsmith@example.com"
    	primary: true
    	type: "work"

    groups:
    	value: "1001"
    	display: "firstGroup"

    	value: "1002"
    	display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
    	isAdmin: false
    	isOkta: true
    	departmentName: "Cloud Service"


    [ 20-06-2014 09:26:30.493 ] [  INFO] - checkUserExists: The ID 101 will be used as the externalId for this user in Okta
    [ 20-06-2014 09:26:30.493 ] [  INFO] - checkUserExists: The user will be returned as ACTIVE
    [ 20-06-2014 09:26:30.494 ] [  INFO] - OK!

- - -
How to search for a user by two different values. This will generate a SCIM Filter with the OR FilterType and two nested SCIM Filters for each FieldName & FieldValue pair.

    When a single result comes back:
    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=email -arg userIdFieldValue=bjensen@example.com -arg userIdFieldName2=email -arg userIdFieldValue2=my-secondary-email@domain.com
    [ 20-06-2014 09:28:28.071 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=email+eq+%22bjensen%40example.com%22+OR+email+eq+%22my-secondary-email%40domain.com%22&startIndex=1&count=100
    [ 20-06-2014 09:28:28.160 ] [  INFO] - checkUserExists: 1 users returned.
    [ 20-06-2014 09:28:28.205 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user:custom"
    id: "102"
    userName: "admin"
    password: "god"
    active: false
    name:
    	formatted: "Barbara Jensen"
    	givenName: "Barbara"
    	familyName: "Jensen"

    emails:
    	value: "bjensen@example.com"
    	primary: true
    	type: "work"

    groups:
    	value: "1002"
    	display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
    	isAdmin: true
    	isOkta: false
    	departmentName: "Administration"


    [ 20-06-2014 09:28:28.205 ] [  INFO] - checkUserExists: The ID 102 will be used as the externalId for this user in Okta
    [ 20-06-2014 09:28:28.205 ] [  INFO] - checkUserExists: The user will be returned as INACTIVE
    [ 20-06-2014 09:28:28.206 ] [  INFO] - OK!


    When multiple results comes back:
    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=email -arg userIdFieldValue=bjensen@example.com -arg userIdFieldName2=email -arg userIdFieldValue2=jsmith@example.com
    [ 20-06-2014 09:28:39.531 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=email+eq+%22bjensen%40example.com%22+OR+email+eq+%22jsmith%40example.com%22&startIndex=1&count=100
    [ 20-06-2014 09:28:39.622 ] [  INFO] - checkUserExists: 2 users returned.
    [ 20-06-2014 09:28:39.667 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user:custom"
    id: "102"
    userName: "admin"
    password: "god"
    active: false
    name:
    	formatted: "Barbara Jensen"
    	givenName: "Barbara"
    	familyName: "Jensen"

    emails:
    	value: "bjensen@example.com"
    	primary: true
    	type: "work"

    groups:
    	value: "1002"
    	display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
    	isAdmin: true
    	isOkta: false
    	departmentName: "Administration"


    [ 20-06-2014 09:28:39.667 ] [  INFO] - checkUserExists: The ID 102 will be used as the externalId for this user in Okta
    [ 20-06-2014 09:28:39.668 ] [  INFO] - checkUserExists: The user will be returned as INACTIVE
    [ 20-06-2014 09:28:39.669 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user:custom"
    id: "101"
    userName: "okta"
    password: "inSecure"
    active: true
    name:
    	formatted: "John Smith"
    	givenName: "John"
    	familyName: "Smith"

    emails:
    	value: "jsmith@example.com"
    	primary: true
    	type: "work"

    groups:
    	value: "1001"
    	display: "firstGroup"

    	value: "1002"
    	display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
    	isAdmin: false
    	isOkta: true
    	departmentName: "Cloud Service"


    [ 20-06-2014 09:28:39.669 ] [  INFO] - checkUserExists: The ID 101 will be used as the externalId for this user in Okta
    [ 20-06-2014 09:28:39.669 ] [  INFO] - checkUserExists: The user will be returned as ACTIVE
    [ 20-06-2014 09:28:39.669 ] [  INFO] - OK!

- - -
How to search for a user by a custom schema extension property:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method checkUserExists -arg userIdFieldName=urn:okta:onprem_app:1.0:user:custom:departmentName -arg userIdFieldValue="Cloud Service"
    [ 20-06-2014 09:31:23.338 ] [  INFO] - making GET request to http://localhost:8080/Users?filter=urn%3Aokta%3Aonprem_app%3A1.0%3Auser%3Acustom%3AdepartmentName+eq+%22Cloud+Service%22&startIndex=1&count=100
    [ 20-06-2014 09:31:23.428 ] [  INFO] - checkUserExists: 1 users returned.
    [ 20-06-2014 09:31:23.473 ] [  INFO] - checkUserExists: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user:custom"
    id: "101"
    userName: "okta"
    password: "inSecure"
    active: true
    name:
    	formatted: "John Smith"
    	givenName: "John"
    	familyName: "Smith"

    emails:
    	value: "jsmith@example.com"
    	primary: true
    	type: "work"

    groups:
    	value: "1001"
    	display: "firstGroup"

    	value: "1002"
    	display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
    	isAdmin: false
    	isOkta: true
    	departmentName: "Cloud Service"


    [ 20-06-2014 09:31:23.473 ] [  INFO] - checkUserExists: The ID 101 will be used as the externalId for this user in Okta
    [ 20-06-2014 09:31:23.473 ] [  INFO] - checkUserExists: The user will be returned as ACTIVE
    [ 20-06-2014 09:31:23.474 ] [  INFO] - OK!



importUserProfile
---------------
importUserProfile will ask your connector to return a single user by passing it the user's id, it tests the SCIMService.getUser connector method. Requires the additional property: id.

The test below will make a request to your SCIM connector asking for a user with the id of 101.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method importUserProfile -arg id=101
    [ 04-10-2013 13:57:54.092 ] [  INFO] - making GET request to http://localhost:8080/Users/101
    [ 04-10-2013 13:57:54.203 ] [  INFO] - importUserProfile: User returned from Connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:scim:schemas:extension:enterprise:1.0", "urn:okta:onprem_app:1.0:user"
    id: "101"
    userName: "okta"
    name:
        formatted: "John Smith"
        givenName: "John"
        familyName: "Smith"
        middleName: "William"

    emails:
        value: "jsmith@example.com"
        primary: true
        type: "work"

    active: true
    password: "inSecure"
    groups:
        value: "1001"
        display: "firstGroup"

        value: "1002"
        display: "secondGroup"

    urn:okta:onprem_app:1.0:user:custom:
        isAdmin: false
        isOkta: true
        departmentName: "Cloud Service"

    [ 04-10-2013 13:57:54.204 ] [  INFO] - importUserProfile: The ID 101 will be used as the id for this user in Okta
    [ 04-10-2013 13:57:54.204 ] [  INFO] - OK!


- - -
How to search for a user that you expect not to exist:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method importUserProfile -arg id=invalidExternalId -expectResults false
    [ 04-10-2013 14:00:01.081 ] [  INFO] - making GET request to http://localhost:8080/Users/invalidExternalId
    [ 04-10-2013 14:00:01.245 ] [  WARN] - error status of 404 received from http://localhost:8080/Users/invalidExternalId
    [ 04-10-2013 14:00:01.245 ] [  INFO] - importUserProfile: No users returned from server. This should be expected.
    [ 04-10-2013 14:00:01.246 ] [  INFO] - OK!

- - -
How to search for a user that you expect but nothing is actually returned:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method importUserProfile -arg id=103
    [ 04-10-2013 14:00:52.096 ] [  INFO] - making GET request to http://localhost:8080/Users/103
    [ 04-10-2013 14:00:52.191 ] [  WARN] - error status of 404 received from http://localhost:8080/Users/103
    [ 04-10-2013 14:00:52.191 ] [ ERROR] - Expected results from importUserProfile but did not get anything.



activateUser
---------------
activateUser will ask your connector to activate an existing user, it tests the SCIMService.updateUser connector method.

The test below will make a request to your SCIM connector asking you to update the User. Since this is a test to activate the user, the active field will always be true.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method activateUser -file data/activateUser.json
    [ 10-10-2013 14:29:00.211 ] [  INFO] - making PUT request to http://localhost:8080/Users/101
    [ 10-10-2013 14:29:00.598 ] [  INFO] - activateUser: will return to Okta that the user's active state is: true
    [ 10-10-2013 14:29:00.598 ] [  INFO] - OK!



deactivateUser
---------------
deactivateUser will ask your connector to deactivate an existing user, it tests the SCIMService.updateUser connector method.

The test below will make a request to your SCIM connector asking you to update the User. Since this is a test to deactivate the user, the active field will always be false.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method deactivateUser -file data/deactivateUser.json
    [ 10-10-2013 14:32:51.211 ] [  INFO] - making PUT request to http://localhost:8080/Users/101
    [ 10-10-2013 14:32:52.171 ] [  INFO] - NOTE: deactivateUser does not send the user returned from the connector back to Okta. Okta assumes that a non-error response from your connector means the deactivateUser methods was successful.
    [ 10-10-2013 14:32:52.598 ] [  INFO] - OK!



reactivateUser
---------------
reactivateUser will ask your connector to activate a previously deactivated user, it tests the SCIMService.updateUser connector method.

The test below will make a request to your SCIM connector asking you to update the User. Since this is a test to reactivate the user, the active field will always be true.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method reactivateUser -file data/reactivateUser.json
    [ 10-10-2013 14:35:04.704 ] [  INFO] - making PUT request to http://localhost:8080/Users/101
    [ 10-10-2013 14:35:04.828 ] [  INFO] - NOTE: reactivateUser does not send the user returned from the connector back to Okta. Okta assumes that a non-error response from your connector means the reactivateUser methods was successful.
    [ 10-10-2013 14:35:04.828 ] [  INFO] - OK!



pushPasswordUpdate
---------------
pushPasswordUpdate will ask your connector to update the password of an existing user, it tests the SCIMService.updateUser connector method.

The test below will make a request to your SCIM connector asking you to update the User. Even though on the password has changed, the entire user object will be supplied to you.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method pushPasswordUpdate -file data/pushPasswordUpdate.json
    [ 10-10-2013 14:36:52.029 ] [  INFO] - making PUT request to http://localhost:8080/Users/101
    [ 10-10-2013 14:36:52.124 ] [  INFO] - NOTE: pushPasswordUpdate does not send the user returned from the connector back to Okta. Okta assumes that a non-error response from your connector means the pushPasswordUpdate methods was successful.
    [ 10-10-2013 14:36:52.124 ] [  INFO] - OK!



pushProfileUpdate
---------------
pushProfileUpdate will ask your connector to update the properties of an existing user, it tests the SCIMService.updateUser connector method.

The test below will make a request to your SCIM connector asking you to update the User. The entire user object will be supplied to you, not an object containing only the changed fields.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080/ -method pushProfileUpdate -file data/pushProfileUpdate.json
    [ 10-10-2013 14:39:44.693 ] [  INFO] - making PUT request to http://localhost:8080/Users/101
    [ 10-10-2013 14:39:44.785 ] [  INFO] - NOTE: pushProfileUpdate does not send the user returned from the connector back to Okta. Okta assumes that a non-error response from your connector means the pushProfileUpdate methods was successful.
    [ 10-10-2013 14:39:44.786 ] [  INFO] - OK!


downloadGroups
---------------
downloadGroups will ask your connector to return the full list of groups it tests the SCIMService.getGroups connector method.

The test below will make a request to your SCIM connector asking for all groups and the returned groups will be logged to disk. The test could make multiple requests to your connector if multiple pages of groups exist.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method downloadGroups
    [ 10-10-2013 14:40:55.598 ] [  INFO] - making GET request to http://localhost:8080/Groups?startIndex=1&count=100
    [ 10-10-2013 14:40:55.816 ] [  INFO] - downloadGroups: 2 Groups returned.
    [ 10-10-2013 14:40:55.819 ] [  INFO] - downloadGroups: Groups returned from connector logged to downloadGroups-20131010-144055.txt
    [ 10-10-2013 14:40:55.820 ] [  INFO] - OK!


getGroupById
------------
getGroupById will ask your connector to return a group based on the supplied Id. This tests the SCIMService.getGroup connector method. Requires the additional property: id.

The test below will make a request to your SCIM connector asking you to return the Group. All the properties of the group will be printed.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method getGroupById -arg id=1002
    [ 17-10-2013 18:03:17.270 ] [  INFO] - making GET request to http://localhost:8080/Groups/1002
    [ 17-10-2013 18:03:17.381 ] [  INFO] - getGroupById : Group returned from connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:okta:custom:group:1.0"
    id: "1002"
    members:
	    value: "User-001"
	    display: "First User"

	    value: "User-002"
	    display: "Second User"

    displayName: "AppGroup-Changed"
    urn:okta:custom:group:1.0:
	    description: "This is the changed first group"
    [ 17-10-2013 18:03:17.381 ] [  INFO] - OK!

If a group is not found for the id, then you would see the output like below :

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method getGroupById -arg id=3455
    [ 18-10-2013 10:22:40.733 ] [  INFO] - making GET request to http://localhost:8080/Groups/3455
    [ 18-10-2013 10:22:40.833 ] [  WARN] - error status of 404 received from http://localhost:8080/Groups/3455
    [ 18-10-2013 10:22:40.833 ] [ ERROR] - Expected results from getGroupById but did not get anything.


createGroup
-----------
createGroup will send a group to the connector so that it can be created. This tests the SCIMService.createGroup connector method.
If the same group exists on your system, you should throw a DuplicateGroupException.

The test below will make a request to your SCIM connector asking you to create the group and return it. All the properties of the group will be printed.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method createGroup -file data/createGroup.json
    [ 17-10-2013 18:09:02.457 ] [  INFO] - making POST request to http://localhost:8080/Groups
    [ 17-10-2013 18:09:02.564 ] [  INFO] - Okta will use the ID 1004 to identify this Group in the future.
    [ 17-10-2013 18:09:02.564 ] [  INFO] - Group returned from connector:
    schemas: "urn:scim:schemas:core:1.0", "urn:okta:custom:group:1.0"
    id: "1004"
    members:
        value: "User-003"
        display: "Third User"

        value: "User-004"
        display: "Fourth User"

        value: "User-005"
        display: "Fifth User"

    displayName: "AppGroup-02"
    urn:okta:custom:group:1.0:
        description: "This is the second group"
    [ 17-10-2013 18:09:02.565 ] [  INFO] - OK!

If the connector throws a DuplicateGroupException when asked to create a group, you would see the following output:

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method createGroup -file data/createGroup.json
    [ 18-10-2013 10:29:49.473 ] [  INFO] - making POST request to http://localhost:8080/Groups
    [ 18-10-2013 10:29:49.576 ] [  WARN] - error status of 409 received from http://localhost:8080/Groups
    [ 18-10-2013 10:29:49.577 ] [ ERROR] - Cannot create the group [{
        "schemas": ["urn:scim:schemas:core:1.0", "urn:okta:custom:group:1.0"],
        "displayName": "AppGroup-02",
        "id": "1004",
        "members" : [{"value": "User-003", "display": "Third User"},{"value": "User-004", "display": "Fourth User"},{"value": "User-005", "display": "Fifth User"}],
        "urn:okta:custom:group:1.0":{
            "description":"This is the second group"
        }
    }]. It already exists
    [ 18-10-2013 10:29:49.577 ] [ ERROR] - Duplicate group found. Cannot create the group


updateGroup
-----------
updateGroup will send a group to the connector so that it can be updated. This tests the SCIMService.updateGroup connector method.

The test below will make a request to your SCIM connector asking you to update the group and return it.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method updateGroup -file data/updateGroup.json
    [ 17-10-2013 18:11:11.842 ] [  INFO] - making PUT request to http://localhost:8080/Groups/1002
    [ 17-10-2013 18:11:11.939 ] [  INFO] - NOTE: updateGroup does not send the group returned from the connector back to Okta. Okta assumes that a non-error response from your connector means the updateGroup methods was successful.
    [ 17-10-2013 18:11:11.939 ] [  INFO] - OK!


deleteGroup
-----------
deleteGroup will send an id to the connector so that the group with that id can be deleted. This tests the SCIMService.deleteGroup connector method. Requires the additional property: id.
An EntityNotFoundException should be thrown if a group with that id does not exist.

The test below will make a request to your SCIM connector asking you to delete the group.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method deleteGroup -arg id=1003
    [ 17-10-2013 18:16:27.553 ] [  INFO] - making DELETE request to http://localhost:8080/Groups/1003
    [ 17-10-2013 18:16:27.646 ] [  INFO] - NOTE: deleteGroup does not send any data back to Okta. Okta assumes that a non-error response from your connector means the deleteGroup was successful and the group with the Id 1003 was deleted
    [ 17-10-2013 18:16:27.646 ] [  INFO] - OK!


getImplementedUserManagementCapabilities
-----------
getImplementedUserManagementCapabilities will ask your connector to return the list of UserManagementCapabilities your connector has implemented it tests the SCIMService.getImplementedUserManagementCapabilities connector method.

    $ java -jar scim-sdk-tests.jar -url http://localhost:8080 -method getImplementedUserManagementCapabilities
    [ 20-11-2013 17:51:44.842 ] [  INFO] - making GET request to http://localhost:8080/ServiceProviderConfigs
    [ 20-11-2013 17:51:44.954 ] [  INFO] - getImplementedUserManagementCapabilities: Capabilities found - 9
    [ 20-11-2013 17:51:44.954 ] [  INFO] - 	GROUP_PUSH
    [ 20-11-2013 17:51:44.955 ] [  INFO] - 	IMPORT_NEW_USERS
    [ 20-11-2013 17:51:44.955 ] [  INFO] - 	IMPORT_PROFILE_UPDATES
    [ 20-11-2013 17:51:44.955 ] [  INFO] - 	PUSH_NEW_USERS
    [ 20-11-2013 17:51:44.955 ] [  INFO] - 	PUSH_PASSWORD_UPDATES
    [ 20-11-2013 17:51:44.955 ] [  INFO] - 	PUSH_PENDING_USERS
    [ 20-11-2013 17:51:44.956 ] [  INFO] - 	PUSH_PROFILE_UPDATES
    [ 20-11-2013 17:51:44.956 ] [  INFO] - 	PUSH_USER_DEACTIVATION
    [ 20-11-2013 17:51:44.956 ] [  INFO] - 	REACTIVATE_USERS
    [ 20-11-2013 17:51:44.956 ] [  INFO] - OK!


