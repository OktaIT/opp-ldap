package com.okta.scim.server.example;

import com.okta.scim.util.SCIMUtil;
import com.okta.scim.util.exception.SCIMSerializationException;
import com.okta.scim.util.model.SCIMGroup;
import com.okta.scim.util.model.SCIMGroupQueryResponse;
import com.okta.scim.util.model.SCIMUser;
import com.okta.scim.util.model.SCIMUserQueryResponse;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author rpamidimarri
 */
public class SCIMConnectorUtil {

    private static ObjectMapper mapper = new ObjectMapper();
    private static final Logger LOGGER = Logger.getLogger(SCIMConnectorUtil.class);

    /**
     * Save users to file
     *
     * @param userMap
     * @param usersFilePath
     * @throws Exception
     */
    public static void saveUsersToFile(Map<String, SCIMUser> userMap, String usersFilePath) throws IOException, SCIMSerializationException {
        SCIMUserQueryResponse allUsers = new SCIMUserQueryResponse();
        allUsers.setTotalResults(userMap.size());
        List<SCIMUser> users = new ArrayList<SCIMUser>();
        for (String key : userMap.keySet()) {
            users.add(userMap.get(key));
        }
        //Set the actual results
        allUsers.setScimUsers(users);
        String usersString = null;
        try {
            usersString = SCIMUtil.marshalSCIMUserQueryResponse(allUsers, false);
        } catch (SCIMSerializationException e) {
            LOGGER.error("Cannot serialize the users [" + allUsers + "]", e);
            throw e;
        }

        writeStringToFile(usersFilePath, usersString);
    }

    /**
     * Read the users from a file into a users map
     *
     * @param userMap
     * @param usersFilePath
     * @throws Exception
     */
    public static void readUsersFromFile(Map<String, SCIMUser> userMap, String usersFilePath) throws IOException, SCIMSerializationException {
        JsonNode usersNode = parseFile(usersFilePath);
        if (usersNode == null) {
            return;
        }
        Iterator<JsonNode> it = usersNode.iterator();

        while (it.hasNext()) {
            JsonNode userNode = it.next();
            try {
                SCIMUser user = SCIMUtil.unMarshalSCIMUser(userNode.toString());
                userMap.put(user.getId(), user);
            } catch (SCIMSerializationException e) {
                LOGGER.error("Exception in converting the user [" + userNode.toString() + "] into a string", e);
                throw e;
            }
        }
    }

    /**
     * Read the groups from a file into a groups map
     *
     * @param groupMap
     * @param groupsFilePath
     * @throws Exception
     */
    public static void readGroupsFromFile(Map<String, SCIMGroup> groupMap, String groupsFilePath) throws Exception {
        JsonNode groupsNode = parseFile(groupsFilePath);
        if (groupsNode == null) {
            return;
        }
        Iterator<JsonNode> it = groupsNode.iterator();

        while (it.hasNext()) {
            JsonNode groupNode = it.next();
            try {
                SCIMGroup group = SCIMUtil.unMarshalSCIMGroup(groupNode.toString());
                groupMap.put(group.getId(), group);
            } catch (SCIMSerializationException e) {
                LOGGER.error("Exception in converting the group [" + groupNode.toString() + "] into a string", e);
                throw e;
            }
        }
    }

    /**
     * Parse a file into a json node
     *
     * @param filePath
     * @return
     * @throws Exception
     */
    private static JsonNode parseFile(String filePath) throws IOException {
        String usersString = readFromFile(filePath);

        if (StringUtils.isEmpty(usersString)) {
            LOGGER.error("Empty string found after parsing the file [" + filePath + "]");
            return null;
        }

        JsonNode node = mapper.readTree(usersString);

        return node.get("Resources");
    }

    /**
     * Save groups to a file
     *
     * @param groupMap
     * @param groupsFilePath
     * @throws Exception
     */
    public static void saveGroupsToFile(Map<String, SCIMGroup> groupMap, String groupsFilePath) throws IOException, SCIMSerializationException {
        SCIMGroupQueryResponse allGroups = new SCIMGroupQueryResponse();
        allGroups.setTotalResults(groupMap.size());
        List<SCIMGroup> groups = new ArrayList<SCIMGroup>();
        for (String key : groupMap.keySet()) {
            groups.add(groupMap.get(key));
        }
        //Set the actual results
        allGroups.setScimGroups(groups);
        String groupsString = null;
        try {
            groupsString = SCIMUtil.marshalSCIMGroupQueryResponse(allGroups, false);
        } catch (SCIMSerializationException e) {
            LOGGER.error("Cannot serialize the groups [" + allGroups + "]", e);
        }

        writeStringToFile(groupsFilePath, groupsString);
    }

    public static void writeStringToFile(String filePath, String stringToWrite) throws IOException {
        try {
            FileUtils.writeStringToFile(new File(filePath), stringToWrite);
        } catch (IOException e) {
            LOGGER.error("Cannot write to the file [" + filePath + "]", e);
            throw e;
        }
    }

    private static String readFromFile(String filePath) throws IOException {
        try {
            return FileUtils.readFileToString(new File(filePath));
        } catch (IOException e) {
            LOGGER.error("Cannot read from the file [" + filePath + "]", e);
        }

        return null;
    }
}
