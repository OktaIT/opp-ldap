package com.okta.scim.server.LDAP.connector;
//package com.okta.scim.server.example;

//IMPORTS!
import com.okta.scim.server.capabilities.UserManagementCapabilities;
import com.okta.scim.server.exception.DuplicateGroupException;
import com.okta.scim.server.exception.EntityNotFoundException;
import com.okta.scim.server.exception.OnPremUserManagementException;
import com.okta.scim.util.exception.InvalidDataTypeException;
import com.okta.scim.server.service.SCIMOktaConstants;
import com.okta.scim.server.service.SCIMService;
import com.okta.scim.util.model.Email;
import com.okta.scim.util.model.Membership;
import com.okta.scim.util.model.Name;
import com.okta.scim.util.model.PaginationProperties;
import com.okta.scim.util.model.SCIMFilter;
import com.okta.scim.util.model.SCIMFilterAttribute;
import com.okta.scim.util.model.SCIMFilterType;
import com.okta.scim.util.model.SCIMGroup;
import com.okta.scim.util.model.SCIMGroupQueryResponse;
import com.okta.scim.util.model.SCIMUser;
import com.okta.scim.util.model.SCIMUserQueryResponse;
import com.okta.scim.util.model.PhoneNumber;

import org.apache.log4j.Logger;
import org.codehaus.jackson.JsonNode;
import org.springframework.util.StringUtils;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapRdn;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.ConfigurationException;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.util.Properties;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Iterator;
import java.util.UUID;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.UnsupportedEncodingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.SearchResult;
import javax.naming.directory.InvalidAttributeValueException;
import javax.naming.NamingEnumeration;
import javax.naming.Context;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.NamingException;
import javax.annotation.PostConstruct;
import javax.xml.parsers.SAXParser;

public class SCIMServiceImpl implements SCIMService {
	//Absolute path for users.json set in the dispatcher-servlet.xml
	private String usersFilePath;
	//Absolute path for groups.json set in the dispatcher-servlet.xml
	private String groupsFilePath;
	//Ldap settings
	private String ldapBaseDn;
	private String ldapGroupDn;
	private String ldapUserDn;
	private String ldapUserPre;
	private String ldapGroupPre;
	private String ldapUserFilter;
	private String ldapGroupFilter;
	private String ldapInitialContextFactory;
	private String ldapUrl;
	private String ldapSecurityAuthentication;
	private String ldapSecurityPrincipal;
	private String ldapSecurityCredentials;
	private String[] ldapUserClass;
	private String[] ldapGroupClass;
	private Map<String, String> ldapUserCore = new HashMap<String, String>();
	private Map<String, String[]> ldapUserCustom = new HashMap<String, String[]>();
	private Map<String, String> ldapGroupCore = new HashMap<String, String>();
	private String USER_RESOURCE = "user";
	private String GROUP_RESOURCE = "group";
	//This should be the name of the App you created. On the Okta URL for the App, you can find this name
	private String appName;
	//Field names for the custom properties
	private static final String CUSTOM_SCHEMA_PROPERTY_IS_ADMIN = "isAdmin";
	private static final String CUSTOM_SCHEMA_PROPERTY_IS_OKTA = "isOkta";
	private static final String CUSTOM_SCHEMA_PROPERTY_DEPARTMENT_NAME = "departmentName";
	//This should be the name of the Universal Directory schema you created. We are assuming this name is "custom"
	private static final String UD_SCHEMA_NAME = "custom";
	private static final Logger LOGGER = Logger.getLogger(SCIMServiceImpl.class);
	//properties file stored in /Okta-Provisioning-Connector-SDK/example-server/src/main/resources
	private static final String CONF_FILENAME = "connector.properties";

	private Map<String, SCIMUser> userMap = new HashMap<String, SCIMUser>();
	private Map<String, SCIMGroup> groupMap = new HashMap<String, SCIMGroup>();
	private int nextUserId;
	private int nextGroupId;
	private String userCustomUrn;
	private boolean useFilePersistence = true;
	private Hashtable env = new Hashtable(11);

	@PostConstruct
	public void afterCreation() throws Exception {
		LOGGER.debug("TEST");
		initLdapVars();
		userCustomUrn = SCIMOktaConstants.CUSTOM_URN_PREFIX + appName + SCIMOktaConstants.CUSTOM_URN_SUFFIX + UD_SCHEMA_NAME;
		env.put(Context.INITIAL_CONTEXT_FACTORY, ldapInitialContextFactory);
		env.put(Context.PROVIDER_URL, ldapUrl);
		env.put(Context.SECURITY_AUTHENTICATION, ldapSecurityAuthentication);
		env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrincipal);
		env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		nextUserId = 100;
		nextGroupId = 1000;
		initUsers();
		initGroups();
	}

	/**
	 * Helper function that pulls data from properties file.
	 *
	 * @throws ConfigurationException
	 */
	private void initLdapVars() throws ConfigurationException {
		Configuration config;
		String[] userCoreMapHolder;
		String[] userCustomMapHolder;
		String[] groupCoreMapHolder;
		Iterator<String> userCustomIt;
		Iterator<String> userCoreIt;
		Iterator<String> groupCoreIt;
		String customKey;
		String coreKey;
		String groupCoreKey;
		try {
			config = new PropertiesConfiguration(CONF_FILENAME);
			appName = config.getString("OPP.appName");
			ldapBaseDn = config.getString("ldap.baseDn");
			ldapGroupDn = config.getString("ldap.groupDn");
			ldapUserDn = config.getString("ldap.userDn");
			ldapGroupPre = config.getString("ldap.groupPre");
			ldapUserPre = config.getString("ldap.userPre");
			ldapUserFilter = config.getString("ldap.userFilter");
			ldapGroupFilter = config.getString("ldap.groupFilter");
			ldapInitialContextFactory = config.getString("ldap.initialContextFactory");
			ldapUrl = config.getString("ldap.url");
			ldapSecurityAuthentication = config.getString("ldap.securityAuthentication");
			ldapSecurityPrincipal = config.getString("ldap.securityPrincipal");
			ldapSecurityCredentials = config.getString("ldap.securityCredentials");
			ldapUserClass = config.getStringArray("ldap.userClass");
			ldapGroupClass = config.getStringArray("ldap.groupClass");
			userCustomIt = config.getKeys("OPP.userCustomMap");
			userCoreIt = config.getKeys("OPP.userCoreMap");
			groupCoreIt = config.getKeys("OPP.groupCoreMap");
			while(userCustomIt.hasNext()) {
				customKey = userCustomIt.next();
				userCustomMapHolder = config.getStringArray(customKey);
				ldapUserCustom.put(userCustomMapHolder[0].trim(), Arrays.copyOfRange(userCustomMapHolder, 1, userCustomMapHolder.length));
			}
			while(userCoreIt.hasNext()) {
				coreKey = userCoreIt.next();
				userCoreMapHolder = config.getStringArray(coreKey);
				ldapUserCore.put(userCoreMapHolder[0].trim(), userCoreMapHolder[1].trim());
			}
			while(groupCoreIt.hasNext()) {
				groupCoreKey = groupCoreIt.next();
				groupCoreMapHolder = config.getStringArray(groupCoreKey);
				ldapGroupCore.put(groupCoreMapHolder[0].trim(), groupCoreMapHolder[1].trim());
			}
		} catch (ConfigurationException e) {
			handleGeneralException(e);
			throw e;
		}
	}

	/**
	 * Helper method that is called when connector is started.
	 * Rebuilds Users in cache if Users exist in Ldap already.
	 * Not necessary for us, but nice to be able to rebuild cache
	 * when testing.
	 *
	 * @throws NamingException
	 */
	private void initUsers() throws NamingException {
		LdapContext ctx = new InitialLdapContext(env, null);
		String dn = ldapUserDn + ldapBaseDn;
		ctx.setRequestControls(null);
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<?> namingEnum = ctx.search(dn, ldapUserFilter, controls);
		int counter = 0;
		while (namingEnum.hasMore()) {
			SearchResult result = (SearchResult) namingEnum.next();
			Attributes attrs = result.getAttributes();
			SCIMUser user = constructUserFromAttrs(attrs);
			userMap.put(user.getId(), user);
		}
		ctx.close();
		namingEnum.close();
	}

	/**
	 * Helper method that is called when connector is started.
	 * Rebuilds Groups in cache if Groups exist in Ldap already.
	 * Not necessary for us, but nice to be able to rebuild cache
	 * when testing.
	 *
	 * @throws NamingException
	 */
	private void initGroups() throws NamingException {
		LdapContext ctx = new InitialLdapContext(env, null);
		String dn = ldapGroupDn + ldapBaseDn;
		ctx.setRequestControls(null);
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		NamingEnumeration<?> namingEnum = ctx.search(dn, ldapGroupFilter, controls);
		int counter = 0;
		while (namingEnum.hasMore()) {
			SearchResult result = (SearchResult) namingEnum.next();
			Attributes attrs = result.getAttributes();
			SCIMGroup group = constructGroupFromAttrs(attrs);
			groupMap.put(group.getId(), group);
		}
		ctx.close();
		namingEnum.close();
	}

	/**
	 * Methods left from skeleton SDK code. Can't remove or stuff breaks.
	 * None of this is used.
	 */
	public String getUsersFilePath() {
		return usersFilePath;
	}

	public void setUsersFilePath(String usersFilePath) {
		this.usersFilePath = usersFilePath;
	}

	public String getGroupsFilePath() {
		return groupsFilePath;
	}

	public void setGroupsFilePath(String groupsFilePath) {
		this.groupsFilePath = groupsFilePath;
	}
	/**
	 * End Leftovers.
	 *
	 */


	/**
	 * This method creates a user. All the standard attributes of the SCIM User can be retrieved by using the
	 * getters on the SCIMStandardUser member of the SCIMUser object.
	 * <p/>
	 * If there are custom schemas in the SCIMUser input, you can retrieve them by providing the name of the
	 * custom property. (Example : SCIMUser.getStringCustomProperty("schemaName", "customFieldName")), if the
	 * property of string type.
	 * <p/>
	 * This method is invoked when a POST is made to /Users with a SCIM payload representing a user
	 * to be created.
	 * <p/>
	 * NOTE: While the user's group memberships will be populated by Okta, according to the SCIM Spec
	 * (http://www.simplecloud.info/specs/draft-scim-core-schema-01.html#anchor4) that information should be
	 * considered read-only. Group memberships should only be updated through calls to createGroup or updateGroup.
	 *
	 * @param user SCIMUser representation of the SCIM String payload sent by the SCIM client.
	 * @return the created SCIMUser.
	 * @throws OnPremUserManagementException
	 */
	@Override
	public SCIMUser createUser(SCIMUser user) throws OnPremUserManagementException {
		String id = generateNextId(USER_RESOURCE);
		user.setId(id);
		LOGGER.info("[createUser] Creating User: " + user.getName().getFormattedName());
		if (userMap == null) {
		throw new OnPremUserManagementException("o01234", "Cannot create the user. The userMap is null", "http://some-help-url", null);
		}
		try {
			LdapContext ctx = new InitialLdapContext(env, null);
			Attributes attrs = constructAttrsFromUser(user);
			Name fullName = user.getName();
			String dn = ldapUserPre + user.getUserName() + "," + ldapUserDn + ldapBaseDn;
			ctx.createSubcontext(dn, attrs);
			ctx.close();
			userMap.put(user.getId(), user);
			LOGGER.debug("[createUser] User " + user.getName().getFormattedName() + " successfully inserted into Directory Service.");
		} catch (NamingException | InvalidDataTypeException e) {
			handleGeneralException(e);
			LOGGER.error(e.getMessage());
			throw new OnPremUserManagementException("o01234", e.getMessage(), e);
		}
		return user;
	}

	/**
	 * This method updates a user.
	 * <p/>
	 * This method is invoked when a PUT is made to /Users/{id} with the SCIM payload representing a user to
	 * be updated.
	 * <p/>
	 * NOTE: While the user's group memberships will be populated by Okta, according to the SCIM Spec
	 * (http://www.simplecloud.info/specs/draft-scim-core-schema-01.html#anchor4) that information should be
	 * considered read-only. Group memberships should only be updated through calls to createGroup or updateGroup.
	 *
	 * @param id   the id of the SCIM user.
	 * @param user SCIMUser representation of the SCIM String payload sent by the SCIM client.
	 * @return the updated SCIMUser.
	 * @throws OnPremUserManagementException
	 */
	public SCIMUser updateUser(String id, SCIMUser user) throws OnPremUserManagementException, EntityNotFoundException {
		if (userMap == null) {
			throw new OnPremUserManagementException("o12345", "Cannot update the user. The userMap is null");
		}
		LOGGER.debug("[updateUser] Updating user: " + user.getName().getFormattedName());
		SCIMUser existingUser = userMap.get(id);
		if (existingUser != null) {
			userMap.put(id, user);
			Name fullName = existingUser.getName();
			try {
				LdapContext ctx = new InitialLdapContext(env, null);
				String dn = ldapUserPre + user.getUserName() + "," + ldapUserDn + ldapBaseDn;
				ctx.destroySubcontext(dn);

				LOGGER.info("[updateUser] User " + user.getName().getFormattedName() + " successfully deleted from Directory Service.");
				if(user.isActive()) {
					LOGGER.info("[updateUser] User is still active, re-adding user.");
					Attributes attrs = constructAttrsFromUser(user);
					ctx.createSubcontext(dn, attrs);
					//this.createUser(user);
				}
				ctx.close();
			} catch (InvalidDataTypeException | NamingException e) {
				handleGeneralException(e);
				throw new OnPremUserManagementException("o01234", e.getMessage(), e);
			}
		} else {
			LOGGER.warn("[updateUser] User " + user.getName().getFormattedName() + " not found, if user is still active, re-adding.");
			if(user.isActive()) {
				this.createUser(user);
			}
		}
		return user;
	}

	/**
	 * Get all the users.
	 * <p/>
	 * This method is invoked when a GET is made to /Users
	 * In order to support pagination (So that the client and the server are not overwhelmed), this method supports querying based on a start index and the
	 * maximum number of results expected by the client. The implementation is responsible for maintaining indices for the SCIM Users.
	 *
	 * @param pageProperties denotes the pagination properties
	 * @param filter         denotes the filter
	 * @return the response from the server, which contains a list of  users along with the total number of results, start index and the items per page
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	public SCIMUserQueryResponse getUsers(PaginationProperties pageProperties, SCIMFilter filter) throws OnPremUserManagementException {
		List<SCIMUser> users = new ArrayList<SCIMUser>();
		LOGGER.debug("[getUsers]");
		if (filter != null) {
			//Get users based on a filter
			users = getUserByFilter(filter);
			//Example to show how to construct a SCIMUserQueryResponse and how to set stuff.
			SCIMUserQueryResponse response = new SCIMUserQueryResponse();
			//The total results in this case is set to the number of users. But it may be possible that
			//there are more results than what is being returned => totalResults > users.size();
			response.setTotalResults(users.size());
			//Actual results which need to be returned
			response.setScimUsers(users);
			//The input has some page properties => Set the start index.
			if (pageProperties != null) {
				response.setStartIndex(pageProperties.getStartIndex());
			}
			return response;
		} else {
			return getUsers(pageProperties);
		}
	}

	private SCIMUserQueryResponse getUsers(PaginationProperties pageProperties) {
		SCIMUserQueryResponse response = new SCIMUserQueryResponse();
		if (userMap == null) {
			//Note that the Error Code "o34567" is arbitrary - You can use any code that you want to.
			throw new OnPremUserManagementException("o34567", "Cannot get the users. The userMap is null");
		}
		int totalResults = userMap.size();
		if (pageProperties != null) {
			//Set the start index to the response.
			response.setStartIndex(pageProperties.getStartIndex());
		}
		//In this example we are setting the total results to the number of results in this page. If there are more
		//results than the number the client asked for (pageProperties.getCount()), then you need to set the total results correctly
		response.setTotalResults(totalResults);
		List<SCIMUser> users = new ArrayList<SCIMUser>();
		for (String key : userMap.keySet()) {
			users.add(userMap.get(key));
		}
		//Set the actual results
		response.setScimUsers(users);
		return response;
	}

	/**
	 * A simple example of how to use <code>SCIMFilter</code> to return a list of users which match the filter criteria.
	 * <p/>
	 * An Admin who configures the UM would specify a SCIM field name as the UniqueId field name. This field and its value would be sent by Okta in the filter.
	 * While implementing the connector, the below points should be noted about the filters.
	 * <p/>
	 * If you choose a single valued attribute as the UserId field name while configuring the App Instance on Okta,
	 * you would get an equality filter here.
	 * For example, if you choose userName, the Filter object below may represent an equality filter like "userName eq "someUserName""
	 * If you choose the name.familyName as the UserId field name, the filter object may represent an equality filter like
	 * "name.familyName eq "someLastName""
	 * If you choose a multivalued attribute (email, for example), the <code>SCIMFilter</code> object below may represent an OR filter consisting of two sub-filters like
	 * "email eq "abc@def.com" OR email eq "def@abc.com""
	 * Of the few multi valued attributes part of the SCIM Core Schema (Like email, address, phone number), only email would be supported as a UserIdField name on Okta.
	 * So, you would have to deal with OR filters only if you choose email.
	 * <p/>
	 * When you get a <code>SCIMFilter</code>, you should check the filter field name (And make sure it is the same field which was configured with Okta), value, condition, etc. as shown in the examples below.
	 *
	 * @param filter the SCIM filter
	 * @return list of users that match the filter
	 */
	private List<SCIMUser> getUserByFilter(SCIMFilter filter) {
		List<SCIMUser> users = new ArrayList<SCIMUser>();
		SCIMFilterType filterType = filter.getFilterType();
		if (filterType.equals(SCIMFilterType.EQUALS)) {
			//Example to show how to deal with an Equality filter
			users = getUsersByEqualityFilter(filter);
		} else if (filterType.equals(SCIMFilterType.OR)) {
			//Example to show how to deal with an OR filter containing multiple sub-filters.
			users = getUsersByOrFilter(filter);
		} else {
			LOGGER.error("The Filter " + filter + " contains a condition that is not supported");
		}
		return users;
	}

	/**
	 * This is an example for how to deal with an OR filter. An OR filter consists of multiple sub equality filters.
	 *
	 * @param filter the OR filter with a set of sub filters expressions
	 * @return list of users that match any of the filters
	 */
	private List<SCIMUser> getUsersByOrFilter(SCIMFilter filter) {
		//An OR filter would contain a list of filter expression. Each expression is a SCIMFilter by itself.
		//Ex : "email eq "abc@def.com" OR email eq "def@abc.com""
		List<SCIMFilter> subFilters = filter.getFilterExpressions();
		LOGGER.info("OR Filter : " + subFilters);
		List<SCIMUser> users = new ArrayList<SCIMUser>();
		//Loop through the sub filters to evaluate each of them.
		//Ex : "email eq "abc@def.com""
		for (SCIMFilter subFilter : subFilters) {
			//Name of the sub filter (email)
			String fieldName = subFilter.getFilterAttribute().getAttributeName();
			//Value (abc@def.com)
			String value = subFilter.getFilterValue();
			//For all the users, check if any of them have this email
			for (Map.Entry<String, SCIMUser> entry : userMap.entrySet()) {
				boolean userFound = false;
				SCIMUser user = entry.getValue();
				//In this example, since we assume that the field name configured with Okta is "email", checking if we got the field name as "email" here
				if (fieldName.equalsIgnoreCase("email")) {
					//Get the user's emails and check if the value is the same as in the filter
					Collection<Email> emails = user.getEmails();
					if (emails != null) {
						for (Email email : emails) {
							if (email.getValue().equalsIgnoreCase(value)) {
								userFound = true;
								break;
							}
						}
					}
				}
				if (userFound) {
					users.add(user);
				}
			}
		}
		return users;
	}

	/**
	 * This is an example of how to deal with an equality filter.<p>
	 * If you choose a custom field/complex field (name.familyName) or any other singular field (userName/externalId), you should get an equality filter here.
	 *
	 * @param filter the EQUALS filter
	 * @return list of users that match the filter
	 */
	private List<SCIMUser> getUsersByEqualityFilter(SCIMFilter filter) {
		String fieldName = filter.getFilterAttribute().getAttributeName();
		String value = filter.getFilterValue();
		LOGGER.info("Equality Filter : Field Name [ " + fieldName + " ]. Value [ " + value + " ]");
		List<SCIMUser> users = new ArrayList<SCIMUser>();
		//A basic example of how to return users that match the criteria
		for (Map.Entry<String, SCIMUser> entry : userMap.entrySet()) {
			SCIMUser user = entry.getValue();
			boolean userFound = false;
			//Ex : "userName eq "someUserName""
			if (fieldName.equalsIgnoreCase("userName")) {
				String userName = user.getUserName();
				if (userName != null && userName.equals(value)) {
					userFound = true;
				}
			} else if (fieldName.equalsIgnoreCase("id")) {
				//"id eq "someId""
				String id = user.getId();
				if (id != null && id.equals(value)) {
					userFound = true;
				}
			} else if (fieldName.equalsIgnoreCase("name")) {
				String subFieldName = filter.getFilterAttribute().getSubAttributeName();
				Name name = user.getName();
				if (name == null || subFieldName == null) {
					continue;
				}
				if (subFieldName.equalsIgnoreCase("familyName")) {
					//"name.familyName eq "someFamilyName""
					String familyName = name.getLastName();
					if (familyName != null && familyName.equals(value)) {
						userFound = true;
					}
				} else if (subFieldName.equalsIgnoreCase("givenName")) {
					//"name.givenName eq "someGivenName""
					String givenName = name.getFirstName();
					if (givenName != null && givenName.equals(value)) {
						userFound = true;
					}
				}
			} else if (filter.getFilterAttribute().getSchema().equalsIgnoreCase(userCustomUrn)) { //Check that the Schema name is the Custom Schema name to process the filter for custom fields
				//"urn:okta:onprem_app:1.0:user:custom:departmentName eq "someValue""
				Map<String, JsonNode> customPropertiesMap = user.getCustomPropertiesMap();
				//Get the custom properties map (SchemaName -> JsonNode)
				if (customPropertiesMap == null || !customPropertiesMap.containsKey(userCustomUrn)) {
					continue;
				}
				//Get the JsonNode having all the custom properties for this schema
				JsonNode customNode = customPropertiesMap.get(userCustomUrn);
				//Check if the node has that custom field
				if (customNode.has(fieldName) && customNode.get(fieldName).asText().equalsIgnoreCase(value)) {
					userFound = true;
				}
			}
			if (userFound) {
				users.add(user);
			}
		}
		return users;
	}

	/**
	 * Get a particular user.
	 * <p/>
	 * This method is invoked when a GET is made to /Users/{id}
	 *
	 * @param id the Id of the SCIM User
	 * @return the user corresponding to the id
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	@Override
	public SCIMUser getUser(String id) throws OnPremUserManagementException, EntityNotFoundException {
		SCIMUser user = userMap.get(id);
		if (user != null) {
			return user;
		} else {
			//If you do not find a user/group by the ID, you can throw this exception.
			throw new EntityNotFoundException();
		}
	}

	/**
	 * This method creates a group. All the standard attributes of the SCIM group can be retrieved by using the
	 * getters on the SCIMStandardGroup member of the SCIMGroup object.
	 * <p/>
	 * If there are custom schemas in the SCIMGroup input, you can retrieve them by providing the name of the
	 * custom property. (Example : SCIMGroup.getCustomProperty("schemaName", "customFieldName"))
	 * <p/>
	 * This method is invoked when a POST is made to /Groups with a SCIM payload representing a group
	 * to be created.
	 *
	 * @param group SCIMGroup representation of the SCIM String payload sent by the SCIM client
	 * @return the created SCIMGroup
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	@Override
	public SCIMGroup createGroup(SCIMGroup group) throws OnPremUserManagementException, DuplicateGroupException {
		String displayName = group.getDisplayName();
		LOGGER.debug("[createGroup] Creating group: " + group.getDisplayName());
		boolean duplicate = false;
		if (groupMap == null) {
			throw new OnPremUserManagementException("o23456", "Cannot create the group. The groupMap is null");
		}
		for (Map.Entry<String, SCIMGroup> entry : groupMap.entrySet()) {
			//In this example, let us assume that a group is duplicate if the displayName is the same
			if (entry.getValue().getDisplayName().equalsIgnoreCase(displayName)) {
				duplicate = true;
			}
		}
		if (duplicate) {
			throw new DuplicateGroupException();
		}
		String id = generateNextId(GROUP_RESOURCE);
		group.setId(id);
		try {
			LdapContext ctx = new InitialLdapContext(env, null);
			Attributes attrs = constructAttrsFromGroup(group);
			ctx.createSubcontext(ldapGroupPre + group.getDisplayName() + "," + ldapGroupDn + ldapBaseDn, attrs);
			ctx.close();
			LOGGER.info("[createGroup] Group " + group.getDisplayName() + " successfully created.");
		} catch (NamingException e) {
			handleGeneralException(e);
			throw new OnPremUserManagementException("o01234", e.getMessage(), e);
		}
		groupMap.put(group.getId(), group);
		return group;
	}

	/**
	 * This method updates a group.
	 * <p/>
	 * This method is invoked when a PUT is made to /Groups/{id} with the SCIM payload representing a group to
	 * be updated.
	 *
	 * @param id    the id of the SCIM group
	 * @param group SCIMGroup representation of the SCIM String payload sent by the SCIM client
	 * @return the updated SCIMGroup
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	public SCIMGroup updateGroup(String id, SCIMGroup group) throws OnPremUserManagementException {
		SCIMGroup existingGroup = groupMap.get(id);
		try {
			if (existingGroup != null) {
				LdapContext ctx = new InitialLdapContext(env, null);
				Attributes attrs = constructAttrsFromGroup(group);
				ctx.destroySubcontext(ldapGroupPre + existingGroup.getDisplayName() + "," + ldapGroupDn + ldapBaseDn);
				LOGGER.info("[updateGroup] Group " + group.getDisplayName() + " successfully removed.");
				ctx.createSubcontext(ldapGroupPre + group.getDisplayName() + "," + ldapGroupDn + ldapBaseDn, attrs);
				ctx.close();
				LOGGER.info("[updateGroup] Group " + group.getDisplayName() + " successfully re-created.");
				groupMap.put(id, group);
				return group;
			} else {
				LOGGER.warn("[updateGroup] Group " + id + " not found, trying to add group.");
				LdapContext ctx = new InitialLdapContext(env, null);
				Attributes attrs = constructAttrsFromGroup(group);
				ctx.createSubcontext(ldapGroupPre + group.getDisplayName() + "," + ldapGroupDn + ldapBaseDn, attrs);
				ctx.close();
				LOGGER.info("[updateGroup] Group " + group.getDisplayName() + " successfully created.");
				groupMap.put(id, group);
				return group;
			}
		} catch (Exception e) {
			handleGeneralException(e);
			throw new OnPremUserManagementException("o01234", e.getMessage(), e);
		}
	}

	/**
	 * Get all the groups.
	 * <p/>
	 * This method is invoked when a GET is made to /Groups
	 * In order to support pagination (So that the client and the server) are not overwhelmed, this method supports querying based on a start index and the
	 * maximum number of results expected by the client. The implementation is responsible for maintaining indices for the SCIM groups.
	 *
	 * @param pageProperties @see com.okta.scim.util.model.PaginationProperties An object holding the properties needed for pagination - startindex and the count.
	 * @return SCIMGroupQueryResponse the response from the server containing the total number of results, start index and the items per page along with a list of groups
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	@Override
	public SCIMGroupQueryResponse getGroups(PaginationProperties pageProperties) throws OnPremUserManagementException {
		SCIMGroupQueryResponse response = new SCIMGroupQueryResponse();
		int totalResults = groupMap.size();
		if (pageProperties != null) {
			//Set the start index
			response.setStartIndex(pageProperties.getStartIndex());
		}
		//In this example we are setting the total results to the number of results in this page. If there are more
		//results than the number the client asked for (pageProperties.getCount()), then you need to set the total results correctly
		response.setTotalResults(totalResults);
		List<SCIMGroup> groups = new ArrayList<SCIMGroup>();
		for (String key : groupMap.keySet()) {
			groups.add(groupMap.get(key));
		}
		//Set the actual results
		response.setScimGroups(groups);
		return response;
	}

	/**
	 * Get a particular group.
	 * <p/>
	 * This method is invoked when a GET is made to /Groups/{id}
	 *
	 * @param id the Id of the SCIM group
	 * @return the group corresponding to the id
	 * @throws com.okta.scim.server.exception.OnPremUserManagementException
	 *
	 */
	public SCIMGroup getGroup(String id) throws OnPremUserManagementException {
		SCIMGroup group = groupMap.get(id);
		if (group != null) {
			return group;
		} else {
			//If you do not find a user/group by the ID, you can throw this exception.
			throw new EntityNotFoundException();
		}
	}

	/**
	 * Delete a particular group.
	 * <p/>
	 * This method is invoked when a DELETE is made to /Groups/{id}
	 *
	 * @param id the Id of the SCIM group
	 * @throws OnPremUserManagementException
	 */
	public void deleteGroup(String id) throws OnPremUserManagementException, EntityNotFoundException {
		if (groupMap.containsKey(id)) {
			SCIMGroup group = groupMap.remove(id);
			try {
				LdapContext ctx = new InitialLdapContext(env, null);
				ctx.destroySubcontext(ldapGroupPre + group.getDisplayName() + "," + ldapGroupDn + ldapBaseDn);
				LOGGER.info("[deleteGroup] Deleting group: " + id);
				ctx.close();
			} catch (NamingException e) {
				handleGeneralException(e);
			}
		} else {
			LOGGER.warn("[deleteGroup] Group: " + id + " not found, throwing exception.");
			throw new EntityNotFoundException();
		}
	}

	/**
	 * Get all the Okta User Management capabilities that this SCIM Service has implemented.
	 * <p/>
	 * This method is invoked when a GET is made to /ServiceProviderConfigs. It is called only when you are testing
	 * or modifying your connector configuration from the Okta Application instance UM UI. If you change the return values
	 * at a later time please re-test and re-save your connector settings to have your new return values respected.
	 * <p/>
	 * These User Management capabilities help customize the UI features available to your app instance and tells Okta
	 * all the possible commands that can be sent to your connector.
	 *
	 * @return all the implemented User Management capabilities.
	 */
	public UserManagementCapabilities[] getImplementedUserManagementCapabilities() {
		return UserManagementCapabilities.values();
	}

	/**
	 * Generate the next if for a resource
	 *
	 * @param resourceType
	 * @return
	 */
	private String generateNextId(String resourceType) {
		if (useFilePersistence) {
			return UUID.randomUUID().toString();
		}
		if (resourceType.equals(USER_RESOURCE)) {
			return Integer.toString(nextUserId++);
		}
		if (resourceType.equals(GROUP_RESOURCE)) {
			return Integer.toString(nextGroupId++);
		}
		return null;
	}

/********************************************************************
 ******************** Private helpers not in skeleton ***************
 *********************************************************************
 **/
	/**
	 * Constructs Attributes from a SCIMUser object. Only deals with base attributes,
	 * calls constructCustomAttrsFromUser to add custom values to Attributes.
	 * Uses mappings for custom attributes from properties file.
	 *
	 * @param user - SCIMUser object to pull values from
	 * @return fully built Attributes Object
	 * @throws InvalidDataTypeException
	 */
	private Attributes constructAttrsFromUser(SCIMUser user) throws InvalidDataTypeException {
		String[] keys = ldapUserCore.keySet().toArray(new String[ldapUserCore.size()]);
		String active = user.isActive() ? "active" : "inactive";
		Attributes attrs = new BasicAttributes(true);
		Attribute objclass = new BasicAttribute("objectClass");
		Object value;
		Attribute attr;
		for(int i = 0; i < ldapUserClass.length; i++) objclass.add(ldapUserClass[i]);
		//TODO: fix this, this is ugly
		//For each of the base attribute mappings in properties file, pull the value from user and
		//add it to the attribute object.
		for(int i = 0; i < keys.length; i++) {
			String attrType = ldapUserCore.get(keys[i]);
			attr = new BasicAttribute(attrType);
			if(keys[i].equals("userName")) {
				value = user.getUserName();
			} else if(keys[i].equals("familyName")) {
				value = user.getName().getLastName();
			} else if(keys[i].equals("givenName")) {
				value = user.getName().getFirstName();
			} else if(keys[i].equals("formatted")) {
				value = user.getName().getFormattedName();
			} else if(keys[i].equals("id")) {
				value = user.getId();
			} else if(keys[i].equals("password") && (user.getPassword() != null)) {
				attrs.put(attr);
				continue;
			} else if(keys[i].equals("phoneNumbers") && (user.getPhoneNumbers() != null)) {
				attrs.put(attr);
				continue;
			} else if(keys[i].equals("emails") && (user.getEmails() != null)) {
				attrs.put(attr);
				continue;
			} else {
				continue;
			}
			attr.add(value.toString());
			attrs.put(attr);
		}
		Attribute passwd = attrs.get(ldapUserCore.get("password"));
		Attribute phoneNumsAttr = attrs.get(ldapUserCore.get("phoneNumbers"));
		Attribute emailsAttr = new BasicAttribute(ldapUserCore.get("emails"));
		//Special cases for attributes that are not simple values
		if(user.getPassword() != null) {
			//passwd.add(hashPassword(user.getPassword()));
			passwd.add(user.getPassword());
		}
		if(user.getPhoneNumbers() != null) {
			Object[] phoneNums = user.getPhoneNumbers().toArray();
			for(int i = 0; i < phoneNums.length; i++) {
				PhoneNumber num = (PhoneNumber) phoneNums[i];
				phoneNumsAttr.add(num.getValue() + "," + num.isPrimary() + "," + num.getType().getTypeString());
			}
			attrs.put(phoneNumsAttr);
		}
		if(user.getEmails() != null) {
			Object[] emails = user.getEmails().toArray();
			for(int i = 0; i < emails.length; i++) {
				Email email = (Email) emails[i];//Yo,dawg I hurd you like emails...
				emailsAttr.add(email.getValue() + "|" + email.isPrimary() + "|" + email.getType());
			}
			attrs.put(emailsAttr);
		}
		attrs.put(objclass);
		return constructCustomAttrsFromUser(user, attrs);
	}

	/**
	 * Adds Attribute objs to supplied attrs made from SCIMUser object.
	 * Uses mappings for custom attributes from properties file.
	 *
	 * @param user - SCIMUser object to pull values from
	 * @param attrs - Attributes to add to SCIMUser object
	 * @return fully built Attributes Object
	 * @throws InvalidDataTypeException
	 */
	private Attributes constructCustomAttrsFromUser(SCIMUser user, Attributes attrs) throws InvalidDataTypeException {
		String[] keys = ldapUserCustom.keySet().toArray(new String[ldapUserCustom.size()]);
		String[] configLine;
		String[] emptyArr = new String[0];
		String[] parentNames = emptyArr;
		Attribute customAttr;
		Object value = "";
		//For each custom attribute mapping in properties, get the appropriate custom value and put it in an Attribute obj
		for(int i = 0; i < keys.length; i++) {
			configLine = ldapUserCustom.get(keys[i]);
			parentNames = emptyArr;
			if(configLine.length > 3) parentNames = Arrays.copyOfRange(configLine, 3, configLine.length);
			customAttr = new BasicAttribute(keys[i]);
			if(configLine[0].equals("int"))
				value = user.getCustomIntValue(configLine[1], configLine[2], parentNames);
			else if(configLine[0].equals("boolean"))
				value = user.getCustomBooleanValue(configLine[1], configLine[2], parentNames);
			else if(configLine[0].equals("string"))
				value = user.getCustomStringValue(configLine[1], configLine[2], parentNames);
			else if(configLine[0].equals("double"))
				value = user.getCustomDoubleValue(configLine[1], configLine[2], parentNames);
			else
				throw new OnPremUserManagementException("o12345", "Unexpected type for Custom attrs in config: " + Arrays.toString(configLine));
			if(value != null) {
				customAttr.add(value.toString());
				attrs.put(customAttr);
			} else {
				throw new OnPremUserManagementException("o12345", "Custom Attr: " + Arrays.toString(configLine) + " was null for SCIMUser: " + user.getUserName());
			}
		}
		return attrs;
	}

	/**
	 * Pulls values for base user attributes from Attributes obj and sets it in SCIMUser obj.
	 * Calls constructUserFromCustomAttrs to handle custom attributes.
	 * Mappings obtained from properties file.
	 *
	 * @param attrs - Attributes to add to SCIMUser object
	 * @return fully built SCIMUser object
	 * @throws NamingException
	 */
	private SCIMUser constructUserFromAttrs(Attributes attrs) throws NamingException {
		//create objects, pull in values from attrs using mapping from properties file.
		SCIMUser user = new SCIMUser();
		String formattedNameLookup = ldapUserCore.get("formatted");
		String formattedName = attrs.get(formattedNameLookup).get().toString();//displayName
		String snLookup = ldapUserCore.get("familyName");
		String sn = attrs.get(snLookup).get().toString();//sn
		String givenNameLookup = ldapUserCore.get("givenName");
		String givenName = attrs.get(givenNameLookup).get().toString();
		String idLookup = ldapUserCore.get("id");
		String id = attrs.get(idLookup).get().toString();
		String uidLookup = ldapUserCore.get("userName");
		String uid = attrs.get(uidLookup).get().toString();
		ArrayList<PhoneNumber> phoneNums = new ArrayList<PhoneNumber>();
		ArrayList<Email> emails = new ArrayList<Email>();
		Name fullName = new Name(formattedName, sn, givenName);
		String phoneNumsAttrLookup = ldapUserCore.get("phoneNumbers");
		Attribute phoneNumsAttr = attrs.get(phoneNumsAttrLookup);
		String emailsAttrLookup = ldapUserCore.get("emails");
		Attribute emailsAttr = attrs.get(emailsAttrLookup);
		user.setName(fullName);
		user.setUserName(uid);
		user.setId(id);
		user.setActive(true);
		//for each phone number, parse line from attrs and build PhoneNumber obj
		if(phoneNumsAttr != null) {
			for(int i = 0; i < phoneNumsAttr.size(); i++) {
				String phoneNum = phoneNumsAttr.get(i).toString();
				String[] phoneNumParts = splitString(phoneNum, ",");
				if(phoneNumParts.length > 2) {
					PhoneNumber.PhoneNumberType type = PhoneNumber.PhoneNumberType.valueOf(phoneNumParts[2].toUpperCase());
					PhoneNumber numEntry = new PhoneNumber(phoneNumParts[0], type, Boolean.parseBoolean(phoneNumParts[1]));
					phoneNums.add(numEntry);
				}
				else {
					LOGGER.error("[constructUserFromAttrs] String: " + phoneNum + "was ill formatted, expected 3 segments.");
				}
			}
			user.setPhoneNumbers(phoneNums);
		}
		//same for emails, TODO: can probably do this better
		if(emailsAttr != null) {
			for(int i = 0; i < emailsAttr.size(); i++) {
				String email = emailsAttr.get(i).toString();
				String[] emailParts = splitString(email, "|");
				if(emailParts.length > 2) {
					Email emailEntry = new Email(emailParts[0], emailParts[2], Boolean.parseBoolean(emailParts[1]));
					emails.add(emailEntry);
				}
				else {
					LOGGER.error("[constructUserFromAttrs] String: " + email + "was ill formatted, expected 3 segments.");
				}
			}
			user.setEmails(emails);
		}
		return constructUserFromCustomAttrs(user, attrs);
	}

	/**
	 * Adds custom Attributes to given SCIMUser object. Pulls mapping for custom attrs from
	 * properties file.
	 *
	 * @param user - SCIMUser object to add custom attributes to.
	 * @param attrs - Attributes to add to SCIMUser object
	 * @return fully built SCIMUser object
	 * @throws NamingException
	 */
	private SCIMUser constructUserFromCustomAttrs(SCIMUser user, Attributes attrs) throws NamingException {
		String[] keys = ldapUserCustom.keySet().toArray(new String[ldapUserCustom.size()]);
		String[] configLine;
		String[] emptyArr = new String[0];
		String[] parentNames = emptyArr;
		Attribute customAttr;
		Object value = "";
		//Iterates through all mapped custom attrs from properties file and sets value in user obj.
		for(int i = 0; i < keys.length; i++) {
			configLine = ldapUserCustom.get(keys[i]);
			parentNames = emptyArr;
			//LOGGER.debug(Arrays.toString(configLine));
			if(configLine.length > 3) parentNames = Arrays.copyOfRange(configLine, 3, configLine.length);
			customAttr = attrs.get(keys[i]);
			value = customAttr.get();
			//TODO: make this better
			//set type for value pulled from Attributes
			if(configLine[0].equals("int"))
				user.setCustomIntValue(configLine[1], configLine[2], Integer.parseInt(value.toString()), parentNames);
			else if(configLine[0].equals("boolean"))
				user.setCustomBooleanValue(configLine[1], configLine[2], Boolean.valueOf(value.toString()), parentNames);
			else if(configLine[0].equals("string"))
				user.setCustomStringValue(configLine[1], configLine[2], (String) value, parentNames);
			else if(configLine[0].equals("double"))
				user.setCustomDoubleValue(configLine[1], configLine[2], Double.parseDouble(value.toString()), parentNames);
			else
				throw new OnPremUserManagementException("o12345", "Unexpected type for Custom attrs in config: " + Arrays.toString(configLine));
		}
		return user;
	}

	/**
	 * Builds the Attributes object to insert into LDAP, uses mappings pulled from
	 * properties file.
	 *
	 * @param group - SCIMGroup object to build Attributes object from.
	 * @return Attributes object that resulted from SCIMGroup object
	 */
	private Attributes constructAttrsFromGroup(SCIMGroup group) {
		Attributes attrs = new BasicAttributes(true);
		String[] keys = ldapGroupCore.keySet().toArray(new String[ldapGroupCore.size()]);
		Attribute attr;
		Object value;
		LOGGER.info("[constructAttrsFromGroup] constructing Attrs from group " + group.getDisplayName());
		Attribute objclass = new BasicAttribute("objectClass");
		for(int i = 0; i < ldapGroupClass.length; i++) objclass.add(ldapGroupClass[i]);
		for(int i = 0; i < keys.length; i++) {
			String attrType = ldapGroupCore.get(keys[i]);
			attr = new BasicAttribute(attrType);
			if(keys[i].equals("id")) {
				value = group.getId();
			} else if(keys[i].equals("members") && (group.getMembers() != null)) {
				attrs.put(attr);
				continue;
			} else {
				continue;
			}
			attr.add(value.toString());
			attrs.put(attr);
		}
		Attribute member = attrs.get(ldapGroupCore.get("members"));
		attrs.put(objclass);
		//builds dn from all members, assumes the members are located in the same area as users.
		if(group.getMembers() != null ) {
			Object[] members = group.getMembers().toArray();
			for(int i = 0; i < members.length; i++) {
				Membership mem = (Membership) members[i];
				String name = ldapUserPre + mem.getDisplayName() + "," + ldapUserDn + ldapBaseDn;
				DistinguishedName dn = new DistinguishedName(name);
				member.add(dn.encode());
			}
		}
		return attrs;
	}

	/**
	 * Helper function that constructs a SCIMGroup object from Attributes
	 * fetched from Ldap. Uses mappings from properties file to set fields in SCIMGroup obj.
	 *
	 * @param attrs - attributes to build SCIMGroup
	 * @return the SCIMGroup object that the attrs created
	 * @throws NamingException
	 */
	private SCIMGroup constructGroupFromAttrs(Attributes attrs) throws NamingException {
		//create objs/get mappings from config file.
		List<SCIMUser> result;
		SCIMGroup group = new SCIMGroup();
		SCIMFilter filter = new SCIMFilter();
		SCIMFilterAttribute filterAttr = new SCIMFilterAttribute();
		SCIMFilterType filterType = SCIMFilterType.EQUALS;
		filter.setFilterType(filterType);
		filterAttr.setAttributeName("userName");
		filter.setFilterAttribute(filterAttr);
		String cn = attrs.get("cn").get().toString();
		LOGGER.debug("[constructGroupFromAttrs] Constructing Group " + cn + " from Attrs.");
		ArrayList<Membership> memberList = new ArrayList<Membership>();
		String memberAttrLookup = ldapGroupCore.get("members");
		Attribute memberAttr = attrs.get(memberAttrLookup);
		String idLookup = ldapGroupCore.get("id");
		String id = attrs.get(idLookup).get().toString();
		group.setDisplayName(cn);
		group.setId(id);
		if(memberAttr != null) {
			for(int i = 0; i < memberAttr.size(); i++) {
				String memberDn = memberAttr.get(i).toString();
				DistinguishedName dn = new DistinguishedName(memberDn);
				LdapRdn memberCn = dn.getLdapRdn("cn");
				filter.setFilterValue(memberCn.getValue());
				//searches through cache to retrieve ids for group memebers,used in SCIMGroup
				result = getUsersByEqualityFilter(filter);
				if(result.size() == 1) {
					SCIMUser resultUser = result.get(0);
					Membership memHolder = new Membership(resultUser.getId(), memberCn.getValue());
					memberList.add(memHolder);
				}
			}
			group.setMembers(memberList);
		}
		return group;
	}

	/**
	 * Helper function, uses MessageDigest to hash with SHA, not actually used for us.
	 *
	 * @param password - the password to hash
	 * @return the result of the hash base 64 encoded
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	private String hashPassword(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		MessageDigest digest = MessageDigest.getInstance("SHA");
		digest.update(password.getBytes("UTF8"));
		byte[] encodedBytes = Base64.encodeBase64(digest.digest());
		String shaPassword = new String(encodedBytes);
		return "{SHA}" + shaPassword;
	}

	/**
	 * Helper function that checks if delimiter exists in string before splitting it.
	 * Probably not super necessary.
	 *
	 * @param s - string to split
	 * @param delim - delimiter to split on
	 * @return result of split operation.
	 */
	private String[] splitString(String s, String delim) throws OnPremUserManagementException{
		if(s.contains(delim)) {
			String[] sParts = s.split(Pattern.quote(delim));//split uses regex, contains uses string literals
			return sParts;
		} else {
			LOGGER.error("[splitString] " + "Cannot parse: " + s + "using delimiter: " + delim);
			throw new OnPremUserManagementException("o2313", "Cannot parse: " + s + "using delimiter: " + delim);
		}
	}

	/**
	 * Helper function to print stack trace to logger.
	 *
	 * @param e - exception to print
	 * @return
	 */
	private void handleGeneralException(Exception e) {
		StringWriter errors = new StringWriter();
		e.printStackTrace(new PrintWriter(errors));
		LOGGER.error(e.getMessage());
		LOGGER.debug(errors.toString());
	}
}

