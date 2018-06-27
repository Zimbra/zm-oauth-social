/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2018 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */

package com.zimbra.oauth.handlers.impl;

import static com.zimbra.common.mailbox.ContactConstants.A_birthday;
import static com.zimbra.common.mailbox.ContactConstants.A_firstName;
import static com.zimbra.common.mailbox.ContactConstants.A_fullName;
import static com.zimbra.common.mailbox.ContactConstants.A_imAddress1;
import static com.zimbra.common.mailbox.ContactConstants.A_lastName;
import static com.zimbra.common.mailbox.ContactConstants.A_middleName;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.httpclient.methods.GetMethod;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.cs.mailbox.Contact;
import com.zimbra.cs.mailbox.Mailbox;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.cs.service.mail.CreateContact;
import com.zimbra.cs.service.util.ItemId;
import com.zimbra.oauth.handlers.impl.FacebookOAuth2Handler.FacebookContactConstants;
import com.zimbra.oauth.handlers.impl.FacebookOAuth2Handler.FacebookOAuthConstants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;

/**
 * The FacebookContactsImport class.<br>
 * Used to sync contacts from the Facebook social service.<br>
 * Source from the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class FacebookContactsImport implements DataImport {

    /**
     * The datasource under import.
     */
    private final DataSource mDataSource;

    /**
     * Configuration wrapper.
     */
    private Configuration config;

    /**
     * Constructor.
     *
     * @param datasource The datasource to set
     */
    public FacebookContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration.buildConfiguration(FacebookOAuthConstants.CLIENT_NAME.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for Facebook: %s",
                e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    @Override
    public void test() throws ServiceException {
        // list of contacts to create after parsing Facebook responses
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = new HashSet<String>();
        String respContent = "";
        try {
            // fetch contacts
            final JsonNode jsonResponse = getContactsRequest(buildContactsUrl(null, refresh()));
            respContent = jsonResponse.toString();
            if (jsonResponse != null && jsonResponse.isContainerNode()) {
                // parse contacts if any, and update the createList
                if (jsonResponse.has("data") && jsonResponse.get("data").isArray()) {
                    final JsonNode jsonContacts = jsonResponse.get("data");
                    parseNewContacts(existingContacts, jsonContacts, "id", createList);
                } else if (jsonResponse.has("error")
                    && jsonResponse.get("error").isContainerNode()) {
                    ZimbraLog.extensions.debug(
                        "Error found in JSON response object. Response body: %s", respContent);
                    throw ServiceException.FAILURE("An error was found in the api response. "
                        + jsonResponse.get("error").asText(""), null);
                } else {
                    ZimbraLog.extensions.debug(
                        "Did not find 'data' element in JSON response object. Response body: %s",
                        respContent);
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object. Response body: %s",
                    respContent);
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Facebook Contacts API for "
                    + "testing. Response body: %s",
                respContent), e);
        }
        if (createList.isEmpty()) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Facebook Contacts API for "
                    + "testing. Response body %s",
                respContent), null);
        }
    }

    /**
     * Retrieves a Facebook user accessToken.
     *
     * @return accessToken the access token to use for requests
     * @throws ServiceException If there are issues
     */
    protected String refresh() throws ServiceException {
        final Account acct = this.mDataSource.getAccount();
        final OAuthInfo oauthInfo = new OAuthInfo(new HashMap<String, String>());
        final String refreshToken = OAuth2DataSource.getRefreshToken(mDataSource);
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(),
                FacebookOAuthConstants.CLIENT_NAME.getValue()),
            FacebookOAuthConstants.CLIENT_NAME.getValue(), acct);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(),
                FacebookOAuthConstants.CLIENT_NAME.getValue()),
            FacebookOAuthConstants.CLIENT_NAME.getValue(), acct);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(),
                FacebookOAuthConstants.CLIENT_NAME.getValue()),
            FacebookOAuthConstants.CLIENT_NAME.getValue(), acct);
        // set client specific properties
        oauthInfo.setRefreshToken(refreshToken);
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(FacebookOAuthConstants.AUTHENTICATE_URI.getValue());

        ZimbraLog.extensions.debug("Fetching access credentials for import.");
        final String codeResponse = getFacebookCodeRequest(oauthInfo);
        final JsonNode credentials = getFacebookRefreshTokenRequest(oauthInfo, codeResponse);
        return credentials.get("access_token").asText();
    }

    /**
     * Requests a fresh access token.
     *
     * @param authInfo The authInfo object used for OAuth details
     * @param code The code from Facebook to use when fetching the access token
     * @return The JSON response
     * @throws ServiceException When errors are encountered making the request
     */
    public static JsonNode getFacebookRefreshTokenRequest(OAuthInfo authInfo, String code)
        throws ServiceException {
        String encodedUrl;
        try {
            encodedUrl = URLEncoder.encode(authInfo.getClientRedirectUri(),
                OAuth2Constants.ENCODING.getValue());
        } catch (final UnsupportedEncodingException e1) {
            ZimbraLog.extensions.errorQuietly("There was an issue encoding the url.", e1);
            throw ServiceException.FAILURE(
                "There was an issue encoding the url. " + authInfo.getClientRedirectUri(), null);
        }
        final String queryString = String.format(
            FacebookOAuthConstants.REFRESH_ACCESS_TOKEN_FOR_CODE_REQUEST_URI_TEMPLATE.getValue(),
            authInfo.getClientId(), encodedUrl, code);

        final GetMethod request = new GetMethod(queryString);
        JsonNode json = null;
        try {
            json = FacebookOAuth2Handler.executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization code.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization code for this user.");
        }
        if (json.has("error") || !json.has("access_token")
            || json.get("access_token").asText().isEmpty()) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue acquiring the authorization code. Response: " + json.toString(),
                null);
            throw ServiceException
                .PERM_DENIED("Required access token from Facebook was not found.");
        }

        return json;
    }

    /**
     * Facebook exchange token request.<br>
     * Request provides an access token<br>
     * .
     *
     * @param authInfo Contains the auth info to use in the request
     * @return code The code value returned from Facebook
     * @throws ServiceException If there are issues performing the request or
     *             parsing for json
     */
    public static String getFacebookCodeRequest(OAuthInfo authInfo) throws ServiceException {
        final String refreshToken = authInfo.getRefreshToken();

        String encodedUrl;
        try {
            encodedUrl = URLEncoder.encode(authInfo.getClientRedirectUri(),
                OAuth2Constants.ENCODING.getValue());
        } catch (final UnsupportedEncodingException e1) {
            ZimbraLog.extensions.errorQuietly("There was an issue encoding the url.", e1);
            throw ServiceException.FAILURE(
                "There was an issue encoding the url. " + authInfo.getClientRedirectUri(), null);
        }

        final String queryString = String.format(
            FacebookOAuthConstants.REFRESH_TOKEN_CODE_REQUEST_URI_TEMPLATE.getValue(), refreshToken,
            authInfo.getClientId(), authInfo.getClientSecret(), encodedUrl);
        final GetMethod request = new GetMethod(queryString);

        JsonNode json = null;
        try {
            json = FacebookOAuth2Handler.executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization code.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization code for this user.");
        }
        String code = null;
        if (!json.has("error") && json.has("code")) {
            code = json.get("code").asText();
        } else {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue acquiring the authorization code. Response: " + json.toString(),
                null);
            throw ServiceException.PERM_DENIED("Required code from Facebook was not found.");
        }
        return code;
    }

    /**
     * Requests contacts for the given credentials.
     *
     * @param url The contacts url
     * @return Json contacts response
     * @throws ServiceException If there are issues retrieving the data
     * @throws IOException If there are issues executing the request
     */
    protected JsonNode getContactsRequest(String url) throws ServiceException, IOException {
        final GetMethod get = new GetMethod(url);
        ZimbraLog.extensions.trace("Fetching contacts for import.");
        return OAuth2Handler.executeRequestForJson(get);
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        final String refreshToken = refresh();
        final Mailbox mailbox = mDataSource.getMailbox();
        final int folderId = mDataSource.getFolderId();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = getExistingContacts(mailbox, folderId, A_imAddress1);

        String respContent = "";
        String nextPageUrl = null;
        try {
            do {
                // build contacts url, query params with access token or use
                // Facebook nextPageUrl if defined
                final String url = buildContactsUrl(nextPageUrl, refreshToken);
                nextPageUrl = null;
                // log this only at the most verbose level, because this
                // contains
                // privileged information
                ZimbraLog.extensions.debug("Attempting to sync Facebook contacts. URL: %s", url);
                final JsonNode jsonResponse = getContactsRequest(url);
                if (jsonResponse != null && jsonResponse.isContainerNode()) {
                    respContent = jsonResponse.toString();
                    if (jsonResponse.has("error")) {
                        ZimbraLog.extensions.debug(
                            "Error found in JSON response object while fetching contacts. Response body: %s",
                            respContent);
                        throw ServiceException.FAILURE("An error was found in the api response. "
                            + jsonResponse.get("error").asText(""), null);
                    }
                    if (jsonResponse.has("data")) {
                        final JsonNode contactsObject = jsonResponse.get("data");
                        createNewContacts(existingContacts, contactsObject);
                        // check for next page
                        if (jsonResponse.has("paging") && jsonResponse.get("paging").has("next")) {
                            nextPageUrl = jsonResponse.get("paging").get("next").asText();
                        }
                    } else {
                        ZimbraLog.extensions
                            .info("Did not find required 'data' node in json object.");
                    }
                } else {
                    ZimbraLog.extensions.debug("Did not find JSON response object.");
                }
            } while (nextPageUrl != null);
        } catch (UnsupportedOperationException | IOException e) {
            ZimbraLog.extensions.debug(String.format(
                "Data source test failed. Failed to fetch contacts from Facebook Contacts API"
                    + "for testing. Response body: %s",
                respContent), e);
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Facebook Contacts API"
                    + "for testing. Response body: %s",
                respContent), e);
        }

    }

    /**
     * Creates new contacts from the Facebook api excluding existing contacts in
     * the datasource.
     *
     * @param existingContacts Existing contacts
     * @param contactsObject JSON from Facebook api response
     * @throws ServiceException If an error is encountered
     */
    protected void createNewContacts(Set<String> existingContacts, JsonNode contactsObject)
        throws ServiceException {
        final List<ParsedContact> contactList = new ArrayList<ParsedContact>();
        parseNewContacts(existingContacts, contactsObject, "id", contactList);

        if (!contactList.isEmpty()) {
            final ItemId iidFolder = new ItemId(mDataSource.getMailbox(),
                mDataSource.getFolderId());
            ZimbraLog.extensions.trace("Creating contacts from parsed list.");
            CreateContact.createContacts(null, mDataSource.getMailbox(), iidFolder, contactList,
                null);
        }
    }

    /**
     * Processes json contacts from Facebook api into a ParsedContact, adding it
     * to a create list if the contact does not already exist in the datasource
     * folder - based on the resourceName property.
     *
     * @param existingContacts Contact resourceNames in the datasource folder
     * @param jsonContacts Json contacts from Facebook api
     * @param matchField The field to match existing contacts with
     * @param createList List of contacts to create
     */
    protected void parseNewContacts(Set<String> existingContacts, JsonNode jsonContacts,
        String matchField, List<ParsedContact> createList) {
        for (final JsonNode contactElement : jsonContacts) {
            try {
                ZimbraLog.extensions.trace("Verifying if new contact for: %s",
                    jsonContacts.toString());
                String resourceName = null;
                if (contactElement.has(matchField)) {
                    resourceName = contactElement.get(matchField).asText();
                }
                // add to list of contacts to create only if it is new
                if (resourceName == null || !existingContacts.contains(resourceName)) {
                    // parse each contact into a Zimbra object
                    final ParsedContact parsedContact = FacebookContactsUtil
                        .parseNewContact(contactElement, mDataSource);
                    createList.add(parsedContact);
                }
            } catch (final ServiceException e) {
                ZimbraLog.extensions.errorQuietly("Unable to parse contact.", e);
                // if we fail to parse one - continue with the rest
            }
        }
    }

    /**
     * Build and return a contacts url if the nextPageUrl is null.
     *
     * @param nextPageUrl The Url from Facebook pagination for the next page
     * @param refreshToken The token used to fetch the contacts
     * @return A Url to fetch contacts
     */
    protected String buildContactsUrl(String nextPageUrl, String refreshToken) {
        if (nextPageUrl != null) {
            return nextPageUrl;
        }
        return String.format(FacebookContactConstants.CONTACTS_URI_TEMPLATE.getValue(), refreshToken,
            FacebookContactConstants.CONTACTS_PAGE_SIZE.getValue());
    }

    /**
     * Retrieves a set of the contacts identifiers that exist in a specified
     * folder.
     *
     * @param mailbox The mailbox
     * @param folderId The folder
     * @param resourceId The unique contact identifier key name
     * @return Set of resourceNames for existing contacts
     * @throws ServiceException If there are issues fetching the contacts
     */
    protected Set<String> getExistingContacts(Mailbox mailbox, int folderId, String resourceId)
        throws ServiceException {
        // fetch the list of existing contacts for the specified folder
        List<Contact> contacts = null;
        try {
            contacts = mailbox.getContactList(null, folderId);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "Failed to retrieve existing contacts during social service contact sync.", e);
            throw ServiceException.FAILURE(
                "Failed to retrieve existing contacts during social service contact sync.", e);
        }

        // create a resourceName set
        final Set<String> contactsIdentifiers = new HashSet<String>();
        for (final Contact contact : contacts) {
            if (contact != null) {
                final String resourceName = contact.get(resourceId);
                if (resourceName != null) {
                    contactsIdentifiers.add(resourceName);
                }
            }
        }

        return contactsIdentifiers;
    }

    /**
     * The FacebookContactsUtil class.<br>
     * Used to parse contacts from the Facebook service.<br>
     * Source from the original YahooContactsUtil class by @author Greg
     * Solovyev.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    @SuppressWarnings("serial")
    public static class FacebookContactsUtil {

        static enum FContactFieldType {
            id,
            name,
            birthday,
            first_name,
            middle_name,
            last_name
        }

        // parts of contact JSON object
        public static final String VALUE = "value";
        public static final String TYPE = "type";
        public static final String FLAGS = "flags";
        public static final String FIELDS = "fields";

        // facebook name field value parts
        public static final String GIVENNAME = "first_name";
        public static final String MIDDLE = "middle_name";
        public static final String FAMILYNAME = "last_name";
        public static final String FULLNAME = "name";

        public static final Map<String, String> NAME_FIELDS_MAP = new HashMap<String, String>() {
            {
                put(A_firstName, GIVENNAME);
                put(A_middleName, MIDDLE);
                put(A_lastName, FAMILYNAME);
                put(A_fullName, FULLNAME);
            }
        };

        /**
         * Parser for birthday fields.
         *
         * @param fieldObject JSON object
         * @param fields Map of fields
         */
        public static void parseBirthdayField(JsonNode fieldObject, Map<String, String> fields) {
            if (fieldObject.has("birthday")) {
                loadField(A_birthday, fieldObject.get("birthday").asText(), fields);
            }
        }

        /**
         * Parser for name fields.
         *
         * @param fieldObject JSON object
         * @param fields Map of fields
         */
        public static void parseNameFields(JsonNode fieldObject, Map<String, String> fields) {
            for (final String key : NAME_FIELDS_MAP.keySet()) {
                if (fieldObject.has(NAME_FIELDS_MAP.get(key))) {
                    loadField(key, fieldObject.get(NAME_FIELDS_MAP.get(key)).asText(), fields);
                }
            }
        }

        /**
         * Parses the value into a map.
         *
         * @param fieldName The field name to map the value to
         * @param value The value to use
         * @param fields the map of fields to populate
         */
        public static void loadField(String fieldName, String value, Map<String, String> fields) {
            if (!value.isEmpty()) {
                fields.put(fieldName, value);
            }
        }

        /**
         * Parse the contact from JSON node.
         *
         * @param jsonContact JSON node containing contact data
         * @param ds DataSource object
         * @return Parsed contact data
         * @throws ServiceException If there was an error parsing the JSON data
         */
        public static ParsedContact parseNewContact(JsonNode jsonContact, DataSource ds)
            throws ServiceException {
            final Map<String, String> contactFields = new HashMap<String, String>();
            // set the Facebook ID as an IM Address
            contactFields.put(A_imAddress1, jsonContact.get("id").asText());
            // sets the name fields from the json
            parseNameFields(jsonContact, contactFields);
            // sets the birthday field
            parseBirthdayField(jsonContact, contactFields);
            if (!contactFields.isEmpty()) {
                return new ParsedContact(contactFields);
            } else {
                return null;
            }
        }
    }

}
