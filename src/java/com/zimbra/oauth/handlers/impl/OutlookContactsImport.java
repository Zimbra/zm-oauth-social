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
import static com.zimbra.common.mailbox.ContactConstants.A_company;
import static com.zimbra.common.mailbox.ContactConstants.A_department;
import static com.zimbra.common.mailbox.ContactConstants.A_email;
import static com.zimbra.common.mailbox.ContactConstants.A_firstName;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCity;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_homePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_homePostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_homeState;
import static com.zimbra.common.mailbox.ContactConstants.A_homeStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_imAddress1;
import static com.zimbra.common.mailbox.ContactConstants.A_image;
import static com.zimbra.common.mailbox.ContactConstants.A_jobTitle;
import static com.zimbra.common.mailbox.ContactConstants.A_lastName;
import static com.zimbra.common.mailbox.ContactConstants.A_middleName;
import static com.zimbra.common.mailbox.ContactConstants.A_mobilePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_nickname;
import static com.zimbra.common.mailbox.ContactConstants.A_notes;
import static com.zimbra.common.mailbox.ContactConstants.A_office;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCity;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_otherPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_otherState;
import static com.zimbra.common.mailbox.ContactConstants.A_otherStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_workCity;
import static com.zimbra.common.mailbox.ContactConstants.A_workCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_workPhone;
import static com.zimbra.common.mailbox.ContactConstants.A_workPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_workState;
import static com.zimbra.common.mailbox.ContactConstants.A_workStreet;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.Pair;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.mailbox.Contact;
import com.zimbra.cs.mailbox.Contact.Attachment;
import com.zimbra.cs.mailbox.Folder;
import com.zimbra.cs.mailbox.Folder.FolderOptions;
import com.zimbra.cs.mailbox.MailItem.Type;
import com.zimbra.cs.mailbox.MailServiceException.NoSuchItemException;
import com.zimbra.cs.mailbox.Mailbox;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.cs.service.mail.CreateContact;
import com.zimbra.cs.service.util.ItemId;
import com.zimbra.oauth.handlers.impl.OutlookContactsImport.OutlookContactsUtil.OContactFieldType;
import com.zimbra.oauth.handlers.impl.OutlookOAuth2Handler.OutlookContactConstants;
import com.zimbra.oauth.handlers.impl.OutlookOAuth2Handler.OutlookOAuth2Constants;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The OutlookContactsImport class.<br>
 * Used to sync contacts from the Outlook social service.<br>
 * Based on the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class OutlookContactsImport implements DataImport {

    /**
     * The datasource under import.
     */
    private final DataSource mDataSource;

    /**
     * Configuration wrapper.
     */
    private Configuration config;

    /**
     * Authorization header for this instance.
     */
    private String authorizationHeader;

    /**
     * Constructor.
     *
     * @param datasource The datasource to set
     */
    public OutlookContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration
                .buildConfiguration(OutlookOAuth2Constants.CLIENT_NAME.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for outlook: %s",
                e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    /**
     * Constructor.
     *
     * @param datasource The datasource to set
     * @param config The config
     */
    public OutlookContactsImport(DataSource datasource, Configuration config) {
        this.mDataSource = datasource;
        this.config = config;
    }

    @Override
    public void test() throws ServiceException {
        // list of contacts to create after parsing outlook responses
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = new HashSet<String>();
        // get a new access token and build the auth header
        authorizationHeader = String.format("Bearer %s", refresh());
        String respContent = "";
        try {
            // fetch contacts
            final JsonNode jsonResponse = getContactsRequest(
                OutlookContactConstants.CONTACTS_URI.getValue(), authorizationHeader);
            respContent = jsonResponse.toString();
            if (jsonResponse != null && jsonResponse.isContainerNode()) {
                // parse contacts if any, and update the createList
                if (jsonResponse.has("value") && jsonResponse.get("value").isArray()) {
                    final JsonNode jsonContacts = jsonResponse.get("value");
                    parseNewContacts(existingContacts, jsonContacts, createList);
                } else {
                    ZimbraLog.extensions.debug(
                        "Did not find 'value' element in JSON response object. Response body: %s",
                        respContent);
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object. Response body: %s",
                    respContent);
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Outlook Contacts API for testing. Response body: %s",
                respContent), e);
        }
        if (createList.isEmpty()) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Outlook Contacts API for testing. Response body %s",
                respContent), null);
        }
    }

    /**
     * Retrieves the Outlook user accessToken.
     *
     * @return accessToken A live access token
     * @throws ServiceException If there are issues
     */
    protected String refresh() throws ServiceException {
        final Account acct = this.mDataSource.getAccount();
        final OAuthInfo oauthInfo = new OAuthInfo(new HashMap<String, String>());
        final String refreshToken = OAuth2DataSource.getRefreshToken(mDataSource);
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue()),
            OutlookOAuth2Constants.CLIENT_NAME.getValue(), acct);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue()),
            OutlookOAuth2Constants.CLIENT_NAME.getValue(), acct);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue()),
            OutlookOAuth2Constants.CLIENT_NAME.getValue(), acct);

        // set client specific properties
        oauthInfo.setRefreshToken(refreshToken);
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(OutlookOAuth2Constants.AUTHENTICATE_URI.getValue());

        ZimbraLog.extensions.debug("Fetching access credentials for import.");
        final JsonNode credentials = OutlookOAuth2Handler.getTokenRequest(oauthInfo,
            OAuth2Utilities.encodeBasicHeader(clientId, clientSecret));

        return credentials.get("access_token").asText();
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
        get.addHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            authorizationHeader);
        get.addHeader("Prefer", "odata.track-changes");
        get.addHeader("Prefer",
            "odata.maxpagesize=" + OutlookContactConstants.CONTACTS_PAGE_SIZE.getValue());
        ZimbraLog.extensions.debug("Fetching contacts for import.");
        return OAuth2Handler.executeRequestForJson(get);
    }

    /**
     * Retrieves a set of the contacts identifiers that exist in a specified
     * folder.
     *
     * @param mailbox The mailbox
     * @param folderId The folder
     * @return Set of outlookIds for existing contacts
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
                "Failed to retrieve existing contacts during Outlook contact sync.", e);
            throw ServiceException
                .FAILURE("Failed to retrieve existing contacts during Outlook contact sync.", e);
        }

        // create a OutlookId set
        final Set<String> contactsIdentifiers = new HashSet<String>();
        for (final Contact contact : contacts) {
            if (contact != null) {
                final String outlookId = contact.get(OutlookContactConstants.CONTACT_ID.getValue());
                if (outlookId != null) {
                    contactsIdentifiers.add(outlookId);
                }
            }
        }
        return contactsIdentifiers;
    }

    /**
     * Creates a contact folder if it doesn't exist.<br>
     * Returns contact folder id.
     *
     * @param mailbox The mailbox associated with the datasource
     * @param parentFolderId The datasource folder id
     * @param folderName Outlook folder display name
     * @return Id of outlook named subfolder, or datasource folder id
     * @throws ServiceException If there are issues fetching or creating the folder
     */
    protected int ensureFolder(Mailbox mailbox, int parentFolderId, String folderName)
        throws ServiceException {
        // folder id to create/fetch, default to parent folder
        int folderId = parentFolderId;
        if (!StringUtils.isEmpty(folderName)) {
            try {
                // search for the subfolder of ds folder by name
                Folder childFolder = null;
                try {
                    childFolder = mailbox.getFolderByName(null, parentFolderId, folderName);
                } catch (final NoSuchItemException e) {
                    // do nothing
                }
                if (childFolder == null) {
                    // create child folder if doesn't exist
                    final FolderOptions opts = new FolderOptions();
                    opts.setDefaultView(Type.CONTACT);
                    childFolder = mailbox.createFolder(null, folderName, parentFolderId, opts);
                }
                // use child folder id
                folderId = childFolder.getId();
            } catch (final ServiceException e) {
                ZimbraLog.extensions.errorQuietly(
                    "Failed to retrieve or create folder during Outlook contact sync.", e);
                throw ServiceException
                    .FAILURE("Failed to retrieve or create folder during Outlook contact sync.", e);
            }
        }
        return folderId;
    }

    /**
     * Processes json contacts from outlook api into a ParsedContact, adding it
     * to a create list if the contact does not already exist in the datasource
     * folder - based on the OutlookId property.
     *
     * @param existingContacts Contact resourceNames in the datasource folder
     * @param jsonContacts Json contacts from outlook api
     * @param createList List of contacts to create
     */
    protected void parseNewContacts(Set<String> existingContacts, JsonNode jsonContacts,
        List<ParsedContact> createList) {
        // reuse client for these image requests
        final HttpClient client = OAuth2Utilities.getHttpClient();
        for (final JsonNode contactElement : jsonContacts) {
            try {
                ZimbraLog.extensions.trace("Verifying if new contact for: %s",
                    contactElement.toString());
                String outlookId = null;
                if (contactElement.has(OContactFieldType.Id.name())) {
                    outlookId = contactElement.get(OContactFieldType.Id.name()).asText();
                }
                // add to list of contacts to create only if it is new
                if (outlookId == null || !existingContacts.contains(outlookId)) {
                    // parse each contact into a Zimbra object
                    final ParsedContact parsedContact = OutlookContactsUtil
                        .parseContact(contactElement, mDataSource, client, authorizationHeader);
                    createList.add(parsedContact);
                }
            } catch (final ServiceException e) {
                ZimbraLog.extensions.errorQuietly("Unable to parse contact.", e);
                // if we fail to parse one - continue with the rest
            }
        }
    }

    /**
     * Retrieves and validates a list of contact folder ids.
     *
     * @param authorizationHeader The authorization header to use in requests
     * @return A list of folder ids
     * @throws ServiceException If there are issues handling the request
     * @throws IOException If there are issues handling the request
     */
    protected List<Pair<String, String>> getContactFolders(String authorizationHeader)
        throws ServiceException, IOException {
        final List<Pair<String, String>> folders = new ArrayList<Pair<String, String>>();
        // add null first for for the root folder
        folders.add(new Pair<String, String>(null, null));
        final HttpGet get = new HttpGet(OutlookContactConstants.CONTACTS_FOLDER_URI.getValue());
        get.addHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authorizationHeader);
        ZimbraLog.extensions.debug("Fetching contact folders to import from.");
        final JsonNode response = OAuth2Handler.executeRequestForJson(get);
        if (response != null && response.has("value")) {
            final JsonNode jsonFolders = response.get("value");
            // if the folder list isn't null loop and add all the Ids to our list
            if (!jsonFolders.isNull() && jsonFolders.isArray()) {
                for (final JsonNode folder : jsonFolders) {
                    if (folder.has("Id") && !folder.get("Id").isNull()
                        && folder.has("DisplayName") && !folder.get("DisplayName").isNull()) {
                        folders.add(new Pair<String, String>(folder.get("Id").asText(),
                            folder.get("DisplayName").asText()));
                    }
                }
            }
        }
        return folders;
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        final Mailbox mailbox = mDataSource.getMailbox();
        final int parentFolderId = mDataSource.getFolderId();
        // list of contacts to create after parsing each outlook response
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();
        // get a new access token and build the auth header
        authorizationHeader = String.format("Bearer %s", refresh());
        try {
            // list of folders {outlookFolderId, displayName} to import contacts from
            final List<Pair<String, String>> contactFolders = getContactFolders(authorizationHeader);
            // loop to import contacts for all folders retrieved
            for (final Pair<String, String> outlookContactFolder : contactFolders) {
                // ensure folder exists, determine which folderId to:
                // - check existing contacts in
                // - create new contacts in
                final int folderId = ensureFolder(mailbox, parentFolderId, outlookContactFolder.getSecond());
                // existing contacts from the datasource (sub)folder
                final Set<String> existingContacts = getExistingContacts(mailbox, folderId);
                // first request behavior differs for each folder
                boolean isFirstRequest = true;
                // use root folder fetch if contactFolderId is null
                String pageUrl = OutlookContactConstants.CONTACTS_URI.getValue();
                if (!StringUtils.isEmpty(outlookContactFolder.getFirst())) {
                    pageUrl = OutlookContactConstants.CONTACTS_FOLDER_URI.getValue() + "/"
                        + outlookContactFolder.getFirst() + "/contacts";
                }
                // loop to handle pagination
                do {
                    // use the pageUrl received in each response after first
                    final String url = pageUrl;
                    // always set an empty page url during pagination
                    pageUrl = null;
                    // empty the create list
                    createList.clear();
                    ZimbraLog.extensions.trace("Attempting to sync Outlook contacts. URL: %s", url);
                    // fetch contacts
                    final JsonNode jsonResponse = getContactsRequest(url, authorizationHeader);
                    if (jsonResponse != null && jsonResponse.isContainerNode()) {
                        final String respContent = jsonResponse.toString();
                        ZimbraLog.extensions.info("Contacts sync response from Outlook %s",
                            respContent);
                        // check for error
                        if (jsonResponse.has("error")) {
                            throw ServiceException.FAILURE(
                                String.format(
                                    "Data source sync failed. Failed to fetch contacts"
                                        + " from Outlook Contacts API. The error was:%s",
                                    jsonResponse.get("error").asText()),
                                new Exception("Contact import returned error."));
                        } else if (jsonResponse.has("value")
                            && jsonResponse.get("value").isArray()) {
                            final JsonNode jsonContacts = jsonResponse.get("value");
                            parseNewContacts(existingContacts, jsonContacts, createList);
                            if (!createList.isEmpty()) {
                                // create the contacts that need to be added
                                ZimbraLog.extensions
                                    .debug("Creating set of contacts from parsed list.");
                                CreateContact.createContacts(null, mailbox,
                                    new ItemId(mailbox, folderId), createList, null);
                            }
                        } else {
                            ZimbraLog.extensions.debug(
                                "Did not find error or values object during contact import.");
                        }
                        if (jsonResponse.has("@odata.deltaLink")) {
                            if (isFirstRequest) {
                                // deltaLink IS the pageToken for first request
                                isFirstRequest = false;
                                pageUrl = jsonResponse.get("@odata.deltaLink").asText();
                            }
                            // don't check for nextLink if deltaLink is
                            // present and this isn't the first request
                        } else if (jsonResponse.has("@odata.nextLink")) {
                            // check for nextLink if deltaLink is not given
                            pageUrl = jsonResponse.get("@odata.nextLink").asText();
                        }
                    } else {
                        ZimbraLog.extensions.error("Did not find JSON response object.");
                    }
                } while (pageUrl != null);
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(
                "Data source sync failed. Failed to fetch contacts from Outlook Contacts API.", e);
        }
    }

    /**
     * The OutlookContactsUtil class.<br>
     * Used to parse contacts from the Outlook social service.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    @SuppressWarnings("serial")
    public static class OutlookContactsUtil {

        static enum OContactFieldType {
            Id,
            EmailAddresses,
            GivenName,
            MiddleName,
            Surname,
            NickName,
            JobTitle,
            CompanyName,
            Department,
            OfficeLocation,
            HomePhones,
            BusinessPhones,
            MobilePhone1,
            PersonalNotes,
            HomeAddress,
            BusinessAddress,
            OtherAddress,
            ImAddresses,
            Birthday
        }

        // parts of contact JSON object
        // outlook field value parts
        public static final Map<String, String> FIELD_MAP = new HashMap<String, String>() {
            {
                put(OContactFieldType.Id.name(), OutlookContactConstants.CONTACT_ID.getValue());
                put(OContactFieldType.GivenName.name(), A_firstName);
                put(OContactFieldType.MiddleName.name(), A_middleName);
                put(OContactFieldType.Surname.name(), A_lastName);
                put(OContactFieldType.NickName.name(), A_nickname);
                put(OContactFieldType.JobTitle.name(), A_jobTitle);
                put(OContactFieldType.CompanyName.name(), A_company);
                put(OContactFieldType.Department.name(), A_department);
                put(OContactFieldType.OfficeLocation.name(), A_office);
                put(OContactFieldType.MobilePhone1.name(), A_mobilePhone);
                put(OContactFieldType.PersonalNotes.name(), A_notes);
                put(OContactFieldType.HomePhones.name(), A_homePhone);
                put(OContactFieldType.BusinessPhones.name(), A_workPhone);
                put(OContactFieldType.ImAddresses.name(), A_imAddress1);
            }
        };

        // outlook address field value parts
        public static final String STREET = "Street";
        public static final String CITY = "City";
        public static final String STATE = "State";
        public static final String POSTALCODE = "PostalCode";
        public static final String COUNTRY = "CountryOrRegion";
        public static final Map<String, List<String>> WORK_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_workStreet, Arrays.asList(STREET));
                put(A_workCity, Arrays.asList(CITY));
                put(A_workState, Arrays.asList(STATE));
                put(A_workPostalCode, Arrays.asList(POSTALCODE));
                put(A_workCountry, Arrays.asList(COUNTRY));
            }
        };
        public static final Map<String, List<String>> HOME_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_homeStreet, Arrays.asList(STREET));
                put(A_homeCity, Arrays.asList(CITY));
                put(A_homeState, Arrays.asList(STATE));
                put(A_homePostalCode, Arrays.asList(POSTALCODE));
                put(A_homeCountry, Arrays.asList(COUNTRY));
            }
        };
        public static final Map<String, List<String>> OTHER_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_otherStreet, Arrays.asList(STREET));
                put(A_otherCity, Arrays.asList(CITY));
                put(A_otherState, Arrays.asList(STATE));
                put(A_otherPostalCode, Arrays.asList(POSTALCODE));
                put(A_otherCountry, Arrays.asList(COUNTRY));
            }
        };
        public static final Map<String, String> EMAIL_FIELDS_MAP = new HashMap<String, String>() {

            {
                put("Address", A_email);
            }
        };

        /**
         * Parses an array of string fields.
         *
         * @param fieldValues The array of fields
         * @param fieldKey The key to add multiples of
         * @param fields The contact fields to update
         */
        public static void parseSimpleFields(JsonNode fieldValues, String fieldKey,
            Map<String, String> fields) {
            int i = 1;
            for (final JsonNode fieldValue : fieldValues) {
                if (fieldValue.isTextual() && !fieldValue.isNull()
                    && !StringUtils.isEmpty(fieldValue.asText())) {
                    final String value = fieldValue.asText();
                    String key = fieldKey;
                    if (fields.containsKey(fieldKey)) {
                        // add numerical if we already have this key
                        key = StringUtils.replace(fieldKey, "1", "") + ++i;
                    }
                    fields.put(key, value);
                }
            }
        }

        /**
         * Uses FIELD_MAP to determine Zimbra fieldKey for a given type.<br>
         * Since this is the default case, we check to see if the type is mapped
         * to a specific key before adding.
         *
         * @param fieldValue The json data containing a value
         * @param key The Outlook key we will map to a Zimbra key
         * @param fields The contact fields to update
         */
        public static void parseSimpleField(JsonNode fieldValue, String key,
            Map<String, String> fields) {
            if (FIELD_MAP.containsKey(key) && fieldValue.isTextual() && !fieldValue.isNull()) {
                final String value = fieldValue.asText();
                if (!StringUtils.isEmpty(value)) {
                    fields.put(FIELD_MAP.get(key), value);
                }
            }
        }

        /**
         * Parses and maps set of outlook fields to Zimbra fields.
         *
         * @param fieldArray The json fields to map
         * @param mappingFields Mapping of outlook key to zimbra field
         * @param fields The contact fields to update
         */
        public static void parseMappingField(JsonNode fieldArray, Map<String, String> mappingFields,
            Map<String, String> fields) {
            int i = 1;
            for (final JsonNode fieldObject : fieldArray) {
                for (final Entry<String, String> mapping : mappingFields.entrySet()) {
                    if (fieldObject.has(mapping.getKey())) {
                        // grab the value
                        final String value = fieldObject.get(mapping.getKey()).asText();
                        String fieldKey = mapping.getValue();
                        // map to Zimbra field numerically if we already have a
                        // value set
                        if (fields.containsKey(fieldKey)) {
                            fieldKey = fieldKey.replace("1", "") + ++i;
                        }
                        fields.put(fieldKey, value);
                    }
                }
            }
        }

        /**
         * Parses a birthday field.
         *
         * @param fieldValue The json data containing a value
         * @param locale Locale from ds
         * @param fields The contact fields to update
         */
        public static void parseBirthdayField(JsonNode fieldValue, Locale locale,
            Map<String, String> fields) {
            if (fieldValue.isTextual() && !fieldValue.isNull()) {
                final String value = fieldValue.asText();
                final DateFormat df = DateFormat.getDateInstance(DateFormat.SHORT, locale);
                Date date = null;
                try {
                    date = new SimpleDateFormat(
                        OutlookContactConstants.CONTACT_BIRTHDAY_FORMAT.getValue()).parse(value);
                } catch (final ParseException e) {
                    // log issue, but continue
                    ZimbraLog.extensions.debug("There was an issue parsing the date field.");
                    return;
                }
                fields.put(A_birthday, df.format(date));
            }
        }

        /**
         * Fetches image from contact photo url and creates an attachment.
         *
         * @param id The contact id
         * @param key The field key
         * @param client The http client to fetch with
         * @param authorizationHeader Auth required to access the photo
         * @param attachments The list of attachments to add to
         */
        public static void parseImageField(String id, String key, HttpClient client,
            String authorizationHeader, List<Attachment> attachments) {
            final String imageUrl = String
                .format(OutlookContactConstants.CONTACTS_PHOTO_URI_TEMPLATE.getValue(), id);
            try {
                // fetch the image
                final HttpGet get = new HttpGet(imageUrl);
                // use authorization
                get.addHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
                    authorizationHeader);
                final HttpResponseWrapper response = OAuth2Utilities.executeRequestRaw(client, get);
                // add to attachments
                final Attachment attachment = OAuth2Utilities.createAttachmentFromResponse(
                    response,
                    key,
                    OutlookContactConstants.CONTACTS_IMAGE_NAME.getValue());
                if (attachment != null) {
                    attachments.add(attachment);
                }
            } catch (ServiceException | IOException e) {
                ZimbraLog.extensions
                    .debug("There was an issue fetching a contact image.");
                // don't fail the rest
            }
        }

        /**
         * Parses an address field given a mapping.
         *
         * @param fieldObject Contains json address data
         * @param targetMap Address type map
         * @param fields The contact fields to update
         */
        public static void parseAddressField(JsonNode fieldObject,
            Map<String, List<String>> targetMap, Map<String, String> fields) {
            if (fieldObject.isObject()) {
                for (final String key : targetMap.keySet()) {
                    parseValuePart(fieldObject, targetMap.get(key), key, fields);
                }
            }
        }

        /**
         * Maps multiple fields to a Zimbra field given a list of parts to look for.
         *
         * @param valueObject Contains json data
         * @param partNames The Outlook parts to fetch and store under the key
         * @param fieldName The Zimbra key to use
         * @param fields The contact fields to update
         */
        public static void parseValuePart(JsonNode valueObject, List<String> partNames,
            String fieldName, Map<String, String> fields) {
            for (final String partName : partNames) {
                if (valueObject.has(partName)) {
                    final JsonNode tmp = valueObject.get(partName);
                    if (tmp != null) {
                        final String szValue = tmp.asText();
                        if (szValue != null && !szValue.isEmpty()) {
                            fields.put(fieldName, szValue);
                            break;
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
         * @param client An http client instance
         * @param authorizationHeader Authorization header for this operation
         * @return A parsed contact
         * @throws ServiceException If there are issues
         */
        public static ParsedContact parseContact(JsonNode jsonContact, DataSource ds,
            HttpClient client, String authorizationHeader) throws ServiceException {
            final Map<String, String> contactFields = new HashMap<String, String>();
            final List<Attachment> attachments = new ArrayList<Attachment>();
            for (final OContactFieldType type : OContactFieldType.values()) {
                if (type != null) {
                    if (jsonContact.has(type.name())) {
                        final JsonNode fieldArray = jsonContact.get(type.name());
                        switch (type) {
                        case HomeAddress:
                            parseAddressField(fieldArray, HOME_ADDRESS_FIELDS_MAP, contactFields);
                            break;
                        case BusinessAddress:
                            parseAddressField(fieldArray, WORK_ADDRESS_FIELDS_MAP, contactFields);
                            break;
                        case OtherAddress:
                            parseAddressField(fieldArray, OTHER_ADDRESS_FIELDS_MAP, contactFields);
                            break;
                        case EmailAddresses:
                            parseMappingField(fieldArray, EMAIL_FIELDS_MAP, contactFields);
                            break;
                        case Birthday:
                            Locale locale = null;
                            if (ds != null) {
                                locale = ds.getAccount().getLocale();
                            }
                            if (locale == null) {
                                try {
                                    locale = Provisioning.getInstance().getConfig().getLocale();
                                } catch (final Exception e) {
                                    ZimbraLog.extensions
                                        .warn("Failed to get locale while parsing a contact");
                                }
                            }
                            if (locale == null) {
                                locale = Locale.US;
                            }
                            parseBirthdayField(fieldArray, locale, contactFields);
                            break;
                        case HomePhones:
                        case BusinessPhones:
                        case ImAddresses:
                            parseSimpleFields(fieldArray, FIELD_MAP.get(type.name()),
                                contactFields);
                            break;
                        // remaining fields are simple
                        case Id:
                            // fetch profile image for this contact
                            OutlookContactsUtil.parseImageField(fieldArray.asText(), A_image,
                                client, authorizationHeader, attachments);
                            // continue on to save the Id
                        case GivenName:
                        case MiddleName:
                        case Surname:
                        case NickName:
                        case JobTitle:
                        case CompanyName:
                        case Department:
                        case OfficeLocation:
                        case MobilePhone1:
                        case PersonalNotes:
                        default:
                            parseSimpleField(fieldArray, type.name(), contactFields);
                            break;
                        }
                    }
                }
            }
            if (!contactFields.isEmpty()) {
                return new ParsedContact(contactFields, attachments);
            } else {
                return null;
            }
        }
    }
}
