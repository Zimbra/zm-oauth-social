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

import static com.zimbra.common.mailbox.ContactConstants.A_description;
import static com.zimbra.common.mailbox.ContactConstants.A_nickname;
import static com.zimbra.common.mailbox.ContactConstants.A_otherURL;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;

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
import com.zimbra.oauth.handlers.impl.TwitterContactsImport.TwitterContactsUtil.TContactFieldType;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterAuthorizationBuilder;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterContactConstants;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterOAuth2Constants;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * The TwitterContactsImport class.<br>
 * Used to sync contacts from the Twitter social service.<br>
 * Based on the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class TwitterContactsImport implements DataImport {

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
    public TwitterContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration.buildConfiguration(TwitterOAuth2Constants.CLIENT_NAME.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for twitter: %s", e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    @Override
    public void test() throws ServiceException {
        final List<ParsedContact> contactList = new LinkedList<ParsedContact>();
        // get an authorization builder for signing the requests
        final TwitterAuthorizationBuilder authBuilder = getAuthorizationBuilder();
        String respContent = "";
        try {
            final String url = buildContactsUrl(null);
            final JsonNode jsonResponse = getContactsRequest(url, authBuilder.build());
            if (jsonResponse != null && jsonResponse.isContainerNode()) {
                respContent = jsonResponse.toString();
                // log only at most verbose level, this contains privileged info
                ZimbraLog.extensions.trace("Contacts sync response from Twitter %s", respContent);
                // check for contacts
                if (jsonResponse.has("users") && jsonResponse.get("users").isArray()) {
                    final JsonNode jsonContacts = jsonResponse.get("users");
                    parseNewContacts(Collections.emptySet(), jsonContacts, contactList);
                } else {
                    ZimbraLog.extensions.debug(
                        "Did not find 'users' element in JSON response object. Response body: %s",
                        respContent);
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object.");
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(
                "Data source test failed. Failed to fetch contacts from Twitter Contacts API.", e);
        }

        if (contactList.isEmpty()) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Twitter Contacts API for testing. Response body %s",
                respContent), null);
        }
    }

    /**
     * Creates a Twitter authorization builder with default twitter values.
     *
     * @return TwitterAuthorizationBuilder instnace with required values for contacts
     * @throws ServiceException If there are issues retrieving credentials
     */
    protected TwitterAuthorizationBuilder getAuthorizationBuilder() throws ServiceException {
        final Account acct = mDataSource.getAccount();
        // grab and split tokens as token::token_secret
        final String refreshToken = OAuth2DataSource.getRefreshToken(mDataSource);
        final String [] tokens = refreshToken.split(TwitterOAuth2Constants.TOKEN_DELIMITER.getValue());
        // ensure token and secret are not missing
        if (tokens == null || tokens.length != 2) {
            ZimbraLog.extensions.error("The datasource token is missing.");
            throw ServiceException.FAILURE("The datasource token is missing", null);
        }
        // fetch client id and secret
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(),
                TwitterOAuth2Constants.CLIENT_NAME.getValue()),
            TwitterOAuth2Constants.CLIENT_NAME.getValue(), acct);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(),
                TwitterOAuth2Constants.CLIENT_NAME.getValue()),
            TwitterOAuth2Constants.CLIENT_NAME.getValue(), acct);
        // make a header builder with default twitter values
        return new TwitterAuthorizationBuilder(clientId, clientSecret)
            .withMethod("GET")
            .withEndpoint(TwitterContactConstants.CONTACTS_URI.getValue())
            .withToken(tokens[0])
            .withTokenSecret(tokens[1])
            .withParam("count", TwitterContactConstants.CONTACTS_PAGE_SIZE.getValue());
    }

    /**
     * Requests contacts for the given credentials.
     *
     * @param url The contacts url
     * @param authorizationHeader The credentials header
     * @return Json contacts response
     * @throws ServiceException If there are issues retrieving the data
     * @throws IOException If there are issues executing the request
     */
    protected JsonNode getContactsRequest(String url, String authorizationHeader)
        throws ServiceException, IOException {
        final HttpGet get = new HttpGet(url);
        get.addHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authorizationHeader);
        ZimbraLog.extensions.debug("Fetching contacts for import.");
        return OAuth2Handler.executeRequestForJson(get);
    }

    /**
     * Retrieves a set of the contacts identifiers that exist in a specified
     * folder.
     *
     * @param mailbox The mailbox
     * @param folderId The folder
     * @return Set of TwitterIds for existing contacts
     * @throws ServiceException If there are issues fetching the contacts
     */
    protected Set<String> getExistingContacts(Mailbox mailbox, int folderId)
        throws ServiceException {
        // fetch the list of existing contacts for the specified folder
        List<Contact> contacts = null;
        try {
            contacts = mailbox.getContactList(null, folderId);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "Failed to retrieve existing contacts during Twitter contact sync.", e);
            throw e;
        }

        // create a TwitterId set
        final Set<String> contactsIdentifiers = new HashSet<String>();
        for (final Contact contact : contacts) {
            if (contact != null) {
                final String twitterId = contact
                    .get(TwitterContactConstants.CONTACT_ID.getValue());
                if (twitterId != null) {
                    contactsIdentifiers.add(twitterId);
                }
            }
        }

        return contactsIdentifiers;
    }

    /**
     * Processes json contacts from twitter api into a ParsedContact, adding it
     * to createlist if the contact does not already exist in the datasource
     * folder - based on the TwitterId zimbra property.
     *
     * @param existingContacts Contact TwitterIds in the datasource folder
     * @param jsonContacts Json contacts from twitter api
     * @param createList List of contacts to create
     */
    protected void parseNewContacts(Set<String> existingContacts, JsonNode jsonContacts,
        List<ParsedContact> createList) {
        // the json field key for the contact identifier
        final String idFieldKey = TContactFieldType.id.name();
        for (final JsonNode contactElement : jsonContacts) {
            try {
                ZimbraLog.extensions.trace("Verifying if new contact for: %s",
                    contactElement.toString());
                JsonNode twitterId = null;
                if (contactElement.has(idFieldKey)) {
                    twitterId = contactElement.get(idFieldKey);
                }
                // add to list of contacts to create only if it is new
                if (twitterId.isNull() || !existingContacts.contains(twitterId.asText())) {
                    // parse each contact into a Zimbra object
                    final ParsedContact parsedContact = TwitterContactsUtil
                        .parseContact(contactElement, mDataSource);
                    createList.add(parsedContact);
                }
            } catch (final ServiceException e) {
                ZimbraLog.extensions.errorQuietly("Unable to parse contact.", e);
                // if we fail to parse one - continue with the rest
            }
        }
    }

    /**
     * Builds the twitter contacts url with some contact request query params.
     *
     * @param pageCursor The token to identify which page we're fetching
     * @return Url with added query params
     * @throws ServiceException If there are issues building
     */
    protected String buildContactsUrl(String pageCursor) throws ServiceException {
        try {
            final URIBuilder builder = new URIBuilder(
                TwitterContactConstants.CONTACTS_URI.getValue());
            // always set page size
            builder.addParameter("count", TwitterContactConstants.CONTACTS_PAGE_SIZE.getValue());

            if (pageCursor != null) {
                // set the page token if it exists
                builder.addParameter("cursor", pageCursor);
            }
            return builder.build().toString();
        } catch (final URISyntaxException e) {
            throw ServiceException.FAILURE("Failed to generate contacts fetch url.", e);
        }
    }

    /**
     * Returns the next page cursor.<br>
     * Returns null if there is no next page.
     *
     * @param cursorContainer The json which contains the `next_cursor` property
     * @return The next page cursor
     */
    protected String getNextPageCursor(JsonNode cursorContainer) {
        String cursor = null;
        if (cursorContainer.has("next_cursor")) {
            final JsonNode tokenJson = cursorContainer.get("next_cursor");
            // null and 0 cursor implies no next page
            if (!tokenJson.isNull() && !StringUtils.equals(tokenJson.asText(), "0")) {
                cursor = tokenJson.asText();
            }
        }
        return cursor;
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        final Mailbox mailbox = mDataSource.getMailbox();
        final int folderId = mDataSource.getFolderId();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = getExistingContacts(mailbox, folderId);
        // get an authorization builder for signing the requests
        final TwitterAuthorizationBuilder authBuilder = getAuthorizationBuilder();
        String respContent = "";
        String pageCursor = null;
        try {
            // loop to handle pagination
            do {
                // build contacts url with current pageCursor
                final String url = buildContactsUrl(pageCursor);
                // set the current cursor on the request signer
                authBuilder.withParam("cursor", pageCursor);
                // always set an empty page cursor during pagination
                pageCursor = null;
                ZimbraLog.extensions.debug("Attempting to sync Twitter contacts.");
                // fetch contacts
                final JsonNode jsonResponse = getContactsRequest(url, authBuilder.build());
                if (jsonResponse != null && jsonResponse.isContainerNode()) {
                    respContent = jsonResponse.toString();
                    // log only at most verbose level, this contains privileged info
                    ZimbraLog.extensions.trace("Contacts sync response from Twitter %s", respContent);
                    // check for errors
                    if (jsonResponse.has("errors")) {
                        throw ServiceException.FAILURE(
                            String.format(
                                "Data source sync failed. Failed to fetch contacts"
                                    + " from Twitter Contacts API. The error was:%s",
                                jsonResponse.findValue("errors")),
                            new Exception("Contact import returned error."));
                    // check for contacts
                    } else if (jsonResponse.has("users") && jsonResponse.get("users").isArray()) {
                        final JsonNode jsonContacts = jsonResponse.get("users");
                        final List<ParsedContact> contactList = new LinkedList<ParsedContact>();
                        parseNewContacts(existingContacts, jsonContacts, contactList);
                        if (!contactList.isEmpty()) {
                            // create the contacts that need to be added
                            ZimbraLog.extensions
                                .debug("Creating set of contacts from parsed list.");
                            CreateContact.createContacts(null, mailbox,
                                new ItemId(mailbox, folderId), contactList, null);
                        }
                    } else {
                        ZimbraLog.extensions.debug(
                            "Did not find 'users' element in JSON response object. Response body: %s",
                            respContent);
                    }
                    // check for next page
                    pageCursor = getNextPageCursor(jsonResponse);
                } else {
                    ZimbraLog.extensions.debug("Did not find JSON response object.");
                }
            } while (pageCursor != null);
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(
                "Data source sync failed. Failed to fetch contacts from Twitter Contacts API.", e);
        }
    }

    /**
     * The TwitterContactsUtil class.<br>
     * Used to parse contacts from the Twitter social service.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    public static class TwitterContactsUtil {

        static enum TContactFieldType {
            id,
            screen_name,
            entities,
            name,
            description
        }

        /**
         * Parses and sets a value field from the given key value pair.
         *
         * @param fieldObject Key value pair
         * @param zimbraFieldKey The zimbra key to set with the value
         * @param fields The contact fields to update
         */
        public static void parseSimpleField(JsonNode fieldObject, String zimbraFieldKey,
            Map<String, String> fields) {
            int i = 1;
            if (!fieldObject.isNull()) {
                // grab the value
                final String value = fieldObject.asText();
                // map numerically if we already have a value
                if (fields.containsKey(zimbraFieldKey)) {
                    zimbraFieldKey = zimbraFieldKey.replace("1", "") + ++i;
                }
                fields.put(zimbraFieldKey, value);
            }
        }

        /**
         * Parses and sets a url field from the given entities object.
         *
         * @param fieldObject Entities object containing the urls list
         * @param zimbraFieldKey The zimbra key to add multiples of
         * @param fields The contact fields to update
         */
        public static void parseUrlField(JsonNode fieldObject, String zimbraFieldKey,
            Map<String, String> fields) {
            if (fieldObject.has("urls")) {
                // grab list of urls
                final JsonNode urlObjects = fieldObject.get("urls");
                // if they're an array then save all expanded urls
                if (!urlObjects.isNull() && urlObjects.isArray()) {
                    int i = 1;
                    for (final JsonNode urlObject : urlObjects) {
                        if (urlObject.has("expanded_url")) {
                            final JsonNode jsonValue = urlObject.get("expanded_url");
                            if (!jsonValue.isNull()) {
                                final String value = jsonValue.asText();
                                String fieldKey = zimbraFieldKey;
                                // map numerically if we already have a value
                                if (fields.containsKey(fieldKey)) {
                                    fieldKey = fieldKey.replace("1", "") + ++i;
                                }
                                fields.put(fieldKey, value);
                            }
                        }
                    }
                }
            }
        }

        /**
         * Parses a contact given json data.
         *
         * @param jsonContact The contact to parse
         * @param ds The ds under operation
         * @return A parsed contact
         * @throws ServiceException If there are issues
         */
        public static ParsedContact parseContact(JsonNode jsonContact, DataSource ds)
            throws ServiceException {
            final Map<String, String> contactFields = new HashMap<String, String>();
            for (final TContactFieldType type : TContactFieldType.values()) {
                if (type != null) {
                    if (jsonContact.has(type.name())) {
                        final JsonNode fieldObject = jsonContact.get(type.name());
                        switch (type) {
                        case id:
                            parseSimpleField(fieldObject,
                                TwitterContactConstants.CONTACT_ID.getValue(), contactFields);
                            break;
                        case screen_name:
                            parseSimpleField(fieldObject, "TwitterScreenName", contactFields);
                            break;
                        case name:
                            parseSimpleField(fieldObject, A_nickname, contactFields);
                            break;
                        case description:
                            parseSimpleField(fieldObject, A_description, contactFields);
                            break;
                        case entities:
                            if (fieldObject.has("url")) {
                                parseUrlField(fieldObject.get("url"), A_otherURL, contactFields);
                            }
                            break;
                        default:
                            parseSimpleField(fieldObject, type.name(), contactFields);
                            break;
                        }
                    }
                }
            }
            if (!contactFields.isEmpty()) {
                return new ParsedContact(contactFields);
            } else {
                return null;
            }
        }
    }
}
