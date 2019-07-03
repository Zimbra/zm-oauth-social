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

import static com.zimbra.common.mailbox.ContactConstants.A_anniversary;
import static com.zimbra.common.mailbox.ContactConstants.A_birthday;
import static com.zimbra.common.mailbox.ContactConstants.A_company;
import static com.zimbra.common.mailbox.ContactConstants.A_department;
import static com.zimbra.common.mailbox.ContactConstants.A_description;
import static com.zimbra.common.mailbox.ContactConstants.A_email;
import static com.zimbra.common.mailbox.ContactConstants.A_firstName;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCity;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_homeFax;
import static com.zimbra.common.mailbox.ContactConstants.A_homePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_homePhone2;
import static com.zimbra.common.mailbox.ContactConstants.A_homePostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_homeState;
import static com.zimbra.common.mailbox.ContactConstants.A_homeStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_homeURL;
import static com.zimbra.common.mailbox.ContactConstants.A_imAddress1;
import static com.zimbra.common.mailbox.ContactConstants.A_image;
import static com.zimbra.common.mailbox.ContactConstants.A_initials;
import static com.zimbra.common.mailbox.ContactConstants.A_jobTitle;
import static com.zimbra.common.mailbox.ContactConstants.A_lastName;
import static com.zimbra.common.mailbox.ContactConstants.A_maidenName;
import static com.zimbra.common.mailbox.ContactConstants.A_middleName;
import static com.zimbra.common.mailbox.ContactConstants.A_mobilePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_namePrefix;
import static com.zimbra.common.mailbox.ContactConstants.A_nameSuffix;
import static com.zimbra.common.mailbox.ContactConstants.A_nickname;
import static com.zimbra.common.mailbox.ContactConstants.A_notes;
import static com.zimbra.common.mailbox.ContactConstants.A_office;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCity;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_otherFax;
import static com.zimbra.common.mailbox.ContactConstants.A_otherPhone;
import static com.zimbra.common.mailbox.ContactConstants.A_otherPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_otherState;
import static com.zimbra.common.mailbox.ContactConstants.A_otherStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_otherURL;
import static com.zimbra.common.mailbox.ContactConstants.A_pager;
import static com.zimbra.common.mailbox.ContactConstants.A_phoneticCompany;
import static com.zimbra.common.mailbox.ContactConstants.A_workCity;
import static com.zimbra.common.mailbox.ContactConstants.A_workCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_workEmail1;
import static com.zimbra.common.mailbox.ContactConstants.A_workFax;
import static com.zimbra.common.mailbox.ContactConstants.A_workMobile;
import static com.zimbra.common.mailbox.ContactConstants.A_workPhone;
import static com.zimbra.common.mailbox.ContactConstants.A_workPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_workState;
import static com.zimbra.common.mailbox.ContactConstants.A_workStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_workURL;

import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.HtmlBodyTextExtractor;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.mailbox.Contact;
import com.zimbra.cs.mailbox.Contact.Attachment;
import com.zimbra.cs.mailbox.Mailbox;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.cs.service.mail.CreateContact;
import com.zimbra.cs.service.util.ItemId;
import com.zimbra.oauth.handlers.impl.GoogleOAuth2Handler.GoogleContactConstants;
import com.zimbra.oauth.handlers.impl.GoogleOAuth2Handler.GoogleOAuth2Constants;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The GoogleContactsImport class.<br>
 * Used to sync contacts from the Google social service.<br>
 * Based on the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class GoogleContactsImport implements DataImport {

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
    public GoogleContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration.buildConfiguration(GoogleOAuth2Constants.CLIENT_NAME.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for google: %s", e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    @Override
    public void test() throws ServiceException {
        // list of contacts to create after parsing google responses
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = new HashSet<String>();
        // get a new access token and build the auth header
        final String authorizationHeader = String.format("Bearer %s", refresh());
        String respContent = "";
        try {
            // fetch contacts
            final JsonNode jsonResponse = getContactsRequest(
                GoogleContactConstants.CONTACTS_URI.getValue(), authorizationHeader);
            respContent = jsonResponse.toString();
            if (jsonResponse != null && jsonResponse.isContainerNode()) {
                // parse contacts if any, and update the createList
                if (jsonResponse.has("connections") && jsonResponse.get("connections").isArray()) {
                    final JsonNode jsonContacts = jsonResponse.get("connections");
                    parseNewContacts(existingContacts, jsonContacts, createList);
                } else {
                    ZimbraLog.extensions.debug(
                        "Did not find 'connections' element in JSON response object. Response body: %s",
                        respContent);
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object. Response body: %s",
                    respContent);
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Google Contacts API for testing. Response body: %s",
                respContent), e);
        }
        if (createList.isEmpty()) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from Google Contacts API for testing. Response body %s",
                respContent), null);
        }
    }

    /**
     * Retrieves the Google user accessToken.
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
                GoogleOAuth2Constants.CLIENT_NAME.getValue()),
            GoogleOAuth2Constants.CLIENT_NAME.getValue(), acct);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(),
                GoogleOAuth2Constants.CLIENT_NAME.getValue()),
            GoogleOAuth2Constants.CLIENT_NAME.getValue(), acct);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(),
                GoogleOAuth2Constants.CLIENT_NAME.getValue()),
            GoogleOAuth2Constants.CLIENT_NAME.getValue(), acct);

        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret)
            || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.FAILURE("Required config(id, secret and redirectUri) parameters are not provided.", null);
        }
        // set client specific properties
        oauthInfo.setRefreshToken(refreshToken);
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(GoogleOAuth2Constants.AUTHENTICATE_URI.getValue());

        ZimbraLog.extensions.debug("Fetching access credentials for import.");
        final JsonNode credentials = GoogleOAuth2Handler.getTokenRequest(oauthInfo,
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
     * @return Set of resourceNames for existing contacts
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
                "Failed to retrieve existing contacts during Google contact sync.", e);
            throw ServiceException
                .FAILURE("Failed to retrieve existing contacts during Google contact sync.", e);
        }

        // create a resourceName set
        final Set<String> contactsIdentifiers = new HashSet<String>();
        for (final Contact contact : contacts) {
            if (contact != null) {
                final String resourceName = contact.get("resourceName");
                if (resourceName != null) {
                    contactsIdentifiers.add(resourceName);
                }
            }
        }

        return contactsIdentifiers;
    }

    /**
     * Processes json contacts from google api into a ParsedContact, adding it
     * to a create list if the contact does not already exist in the datasource
     * folder - based on the resourceName property.
     *
     * @param existingContacts Contact resourceNames in the datasource folder
     * @param jsonContacts Json contacts from google api
     * @param createList List of contacts to create
     */
    protected void parseNewContacts(Set<String> existingContacts, JsonNode jsonContacts,
        List<ParsedContact> createList) {
        for (final JsonNode contactElement : jsonContacts) {
            try {
                ZimbraLog.extensions.trace("Verifying if new contact for: %s",
                    jsonContacts.toString());
                String resourceName = null;
                if (contactElement.has("resourceName")) {
                    resourceName = contactElement.get("resourceName").asText();
                }
                // add to list of contacts to create only if it is new
                if (resourceName == null || !existingContacts.contains(resourceName)) {
                    // parse each contact into a Zimbra object
                    final ParsedContact parsedContact = GoogleContactsUtil
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
     * Builds the url with some dynamic contact request query params.
     *
     * @param url The contact url
     * @param syncToken The token to use when fetching changes
     * @param pageToken The token to identify which page we're fetching
     * @return Query params to add to the url
     * @throws UnsupportedEncodingException If there are issues building
     * @throws ServiceException
     */
    protected String buildContactsUrl(String url, String syncToken, String pageToken)
        throws ServiceException {
        try {
            final URIBuilder builder = new URIBuilder(url);
            if (!StringUtils.isEmpty(syncToken)) {
                // add syncToken if repeated fetch
                builder.addParameter("syncToken", syncToken);
            } else {
                // request a syncToken if first fetch
                builder.addParameter("requestSyncToken", "true");
            }

            // always set page size
            builder.addParameter("pageSize", GoogleContactConstants.CONTACTS_PAGE_SIZE.getValue());

            if (pageToken != null) {
                // set the page token if it exists
                builder.addParameter("pageToken", pageToken);
            }
            return builder.build().toString();
        } catch (final URISyntaxException e) {
            throw ServiceException.FAILURE("Failed to generate contacts fetch url.", e);
        }
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        final Mailbox mailbox = mDataSource.getMailbox();
        final int folderId = mDataSource.getFolderId();
        // existing contacts from the datasource folder
        final Set<String> existingContacts = getExistingContacts(mailbox, folderId);
        // get a new access token and build the auth header
        final String authorizationHeader = String.format("Bearer %s", refresh());
        // fetch the syncToken
        final String[] attrs = mDataSource.getMultiAttr(Provisioning.A_zimbraDataSourceAttribute);
        String syncToken = null;
        if (attrs.length > 0) {
            syncToken = attrs[0];
        }
        String respContent = "";
        String pageToken = null;
        try {
            // loop to handle pagination
            do {
                // build contacts url, query params with syncToken and current
                // pageToken
                final String url = buildContactsUrl(GoogleContactConstants.CONTACTS_URI.getValue(),
                    syncToken, pageToken);
                // always set an empty page token during pagination
                pageToken = null;
                ZimbraLog.extensions.debug("Attempting to sync Google contacts.");
                // fetch contacts
                final JsonNode jsonResponse = getContactsRequest(url, authorizationHeader);
                if (jsonResponse != null && jsonResponse.isContainerNode()) {
                    respContent = jsonResponse.toString();
                    // log only at most verbose level, this contains privileged info
                    ZimbraLog.extensions.trace("Contacts sync response from Google %s", respContent);
                    // check for error
                    if (jsonResponse.has("error")) {
                        throw ServiceException.FAILURE(
                            String.format("Data source sync failed. Failed to fetch contacts"
                                + " from Google Contacts API. The error was:%s", jsonResponse.findValue("error")),
                                new Exception("Contact import returned error.")) ;
                    } else if (jsonResponse.has("connections")
                        && jsonResponse.get("connections").isArray()) {
                        final JsonNode jsonContacts = jsonResponse.get("connections");
                        createNewContacts(existingContacts, jsonContacts);
                    } else {
                        ZimbraLog.extensions.debug(
                            "Did not find 'connections' element in JSON response object. Response body: %s",
                            respContent);
                    }
                    // update the sync token if available
                    if (jsonResponse.has("nextSyncToken")) {
                        syncToken = jsonResponse.get("nextSyncToken").asText();
                        final Map<String, Object> dsAttrs = new HashMap<String, Object>();
                        dsAttrs.put(Provisioning.A_zimbraDataSourceAttribute, syncToken);
                        Provisioning.getInstance().modifyDataSource(mDataSource.getAccount(),
                            mDataSource.getId(), dsAttrs);
                    }
                    // check for next page
                    if (jsonResponse.has("nextPageToken")) {
                        pageToken = jsonResponse.get("nextPageToken").asText();
                    }
                } else {
                    ZimbraLog.extensions.debug("Did not find JSON response object.");
                }
            } while (pageToken != null);
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(
                "Data source sync failed. Failed to fetch contacts from Google Contacts API.", e);
        }
    }


    /**
     * Creates new contacts from the api excluding existing contacts in the datasource.
     *
     * @param existingContacts Existing contacts
     * @param contactsObject JSON from the api response
     * @throws ServiceException If an error is encountered
     */
    protected void createNewContacts(Set<String> existingContacts, JsonNode contactsObject)
            throws ServiceException {
        final List<ParsedContact> contactList = new ArrayList<ParsedContact>();
        parseNewContacts(existingContacts, contactsObject, contactList);
        if (!contactList.isEmpty()) {
            final ItemId iidFolder = new ItemId(mDataSource.getMailbox(), mDataSource.getFolderId());
            // create the contacts that need to be added
            ZimbraLog.extensions
                .debug("Creating set of contacts from parsed list.");
            CreateContact.createContacts(null, mDataSource.getMailbox(), iidFolder, contactList,
                null);
        }
    }

    /**
     * The GoogleContactsUtil class.<br>
     * Used to parse contacts from the Google social service.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    @SuppressWarnings("serial")
    public static class GoogleContactsUtil {

        static enum GContactFieldType {
            resourceName,
            nicknames,
            emailAddresses,
            phoneNumbers,
            organizations,
            biographies,
            urls,
            names,
            addresses,
            birthdays,
            events,
            photos,
            userDefined,
            skills,
            interests,
            braggingRights,
            relationshipInterests,
            relationshipStatuses,
            occupations,
            taglines
        }

        // parts of contact JSON object
        public static final String KEY = "key";
        public static final String VALUE = "value";
        public static final String TYPE = "type";
        public static final String DATE = "date";
        public static final String FIELDS = "fields";

        public static final String DEFAULT_TYPE = "DEFAULT_TYPE";

        // google name field value parts
        public static final String GIVENNAME = "givenName";
        public static final String MIDDLE = "middleName";
        public static final String FAMILYNAME = "familyName";
        public static final String PREFIX = "honorificPrefix";
        public static final String SUFFIX = "honorificSuffix";

        public static final Map<String, String> NAME_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(GIVENNAME, A_firstName);
                put(MIDDLE, A_middleName);
                put(FAMILYNAME, A_lastName);
                put(PREFIX, A_namePrefix);
                put(SUFFIX, A_nameSuffix);
            }
        };

        // google nickname types
        public static final String MAIDEN_NAME = "MAIDEN_NAME";
        public static final String INITIALS = "INITIALS";
        public static final String GPLUS = "GPLUS";

        public static final Map<String, String> NICKNAME_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(DEFAULT_TYPE, A_nickname);
                put(MAIDEN_NAME, A_maidenName);
                put(INITIALS, A_initials);
                put(GPLUS, A_imAddress1);
            }
        };

        // google address field value parts
        public static final String STREET = "streetAddress";
        public static final String EXTENDED_ADDRESS = "extendedAddress";
        public static final String CITY = "city";
        public static final String STATE = "region";
        public static final String POSTALCODE = "postalCode";
        public static final String COUNTRY = "country";
        public static final String COUNTRYCODE = "countryCode";
        public static final Map<String, List<String>> WORK_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_workStreet, Arrays.asList(STREET, EXTENDED_ADDRESS));
                put(A_workCity, Arrays.asList(CITY));
                put(A_workState, Arrays.asList(STATE));
                put(A_workPostalCode, Arrays.asList(POSTALCODE));
                put(A_workCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        public static final Map<String, List<String>> HOME_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_homeStreet, Arrays.asList(STREET, EXTENDED_ADDRESS));
                put(A_homeCity, Arrays.asList(CITY));
                put(A_homeState, Arrays.asList(STATE));
                put(A_homePostalCode, Arrays.asList(POSTALCODE));
                put(A_homeCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        public static final Map<String, List<String>> OTHER_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_otherStreet, Arrays.asList(STREET, EXTENDED_ADDRESS));
                put(A_otherCity, Arrays.asList(CITY));
                put(A_otherState, Arrays.asList(STATE));
                put(A_otherPostalCode, Arrays.asList(POSTALCODE));
                put(A_otherCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        // google date field value parts
        public static final String DAY = "day";
        public static final String MONTH = "month";
        public static final String YEAR = "year";
        public static final Map<String, String> DATE_FIELDS_MAP = new HashMap<String, String>() {

            {
                put("birthday", A_birthday);
                put("anniversary", A_anniversary);
            }
        };
        public static final Map<String, String> PHONE_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(DEFAULT_TYPE, A_homePhone);
                put("home", A_homePhone);
                put("work", A_workPhone);
                put("mobile", A_mobilePhone);
                put("homeFax", A_homeFax);
                put("workFax", A_workFax);
                put("otherFax", A_otherFax);
                put("pager", A_pager);
                put("workMobile", A_workMobile);
                put("workPager", A_pager);
                put("main", A_mobilePhone);
                put("googleVoice", A_homePhone2);
                put("other", A_otherPhone);
            }
        };
        public static final Map<String, String> EMAIL_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(DEFAULT_TYPE, A_email);
                put("home", A_email);
                put("work", A_workEmail1);
            }
        };
        public static final Map<String, String> LINK_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(DEFAULT_TYPE, A_homeURL);
                put("home", A_homeURL);
                put("work", A_workURL);
                put("other", A_otherURL);
            }
        };
        public static final String IMAGE_URL = "url";

        public static final Map<String, String> ORGANIZATIONS_FIELDS_MAP = new HashMap<String, String>() {

            {
                put("name", A_company);
                put("phoneticName", A_phoneticCompany);
                put("title", A_jobTitle);
                put("jobDescription", A_description);
                put("department", A_department);
                put("location", A_office);
            }
        };

        public static void parseKeyValueField(JsonNode fieldArray, Map<String, String> fields) {
            for (final JsonNode fieldObject : fieldArray) {
                if (fieldObject.has(KEY) && fieldObject.has(VALUE)) {
                    final JsonNode key = fieldObject.get(KEY);
                    final JsonNode value = fieldObject.get(VALUE);
                    if (key.isTextual() && value.isTextual()) {
                        fields.put(key.asText(), value.asText());
                    }
                }
            }
        }

        public static void parseSimpleField(JsonNode fieldArray, String zimbraFieldKey,
            Map<String, String> fields) {
            parseSimpleField(fieldArray, zimbraFieldKey, fields, false);
        }

        public static void parseSimpleField(JsonNode fieldArray, String zimbraFieldKey,
            Map<String, String> fields, boolean stripHtml) {
            int i = 1;
            for (final JsonNode fieldObject : fieldArray) {
                if (fieldObject.has(VALUE)) {
                    // grab the value
                    String value = fieldObject.get(VALUE).asText();
                    // map to Zimbra field numerically if we already have a
                    // value set
                    if (fields.containsKey(zimbraFieldKey)) {
                        zimbraFieldKey = zimbraFieldKey.replace("1", "") + ++i;
                    }
                    if (stripHtml) {
                        // extract plain text from value if requested
                        try {
                            value = HtmlBodyTextExtractor.extract(new StringReader(value),
                                value.length());
                        } catch (IOException | SAXException e) {
                            ZimbraLog.extensions.trace(
                                "There was an issue parsing plain text from the html body: %s",
                                value);
                            // continue processing
                        }
                    }
                    fields.put(zimbraFieldKey, value);
                }
            }
        }

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
         * Parses a typed field object array into a Zimbra contact field.<br>
         * The mappingField must specify a default type mapping.
         *
         * @param fieldArray The array of typed objects
         * @param mappingFields The social service key -> zimbra key mapping.
         *            Must contain a default mapping.
         * @param fields The parsed contact fields to update
         */
        public static void parseTypedField(JsonNode fieldArray, Map<String, String> mappingFields,
            Map<String, String> fields) {
            int i = 1;
            for (final JsonNode fieldObject : fieldArray) {
                if (fieldObject.has(VALUE)) {
                    // determine the type of this element so we can map, default
                    // otherwise
                    String type = DEFAULT_TYPE;
                    if (fieldObject.has(TYPE)) {
                        type = fieldObject.get(TYPE).asText();
                    }
                    // grab the value
                    final String value = fieldObject.get(VALUE).asText();
                    // map by type to a Zimbra field key
                    String fieldKey = mappingFields.get(type);
                    if (fieldKey == null) {
                        fieldKey = mappingFields.get(DEFAULT_TYPE);
                    }
                    // map numerically if we already have this key
                    if (fields.containsKey(fieldKey)) {
                        fieldKey = fieldKey.replace("1", "") + ++i;
                    }
                    fields.put(fieldKey, value);
                }
            }
        }

        public static void parseDateField(JsonNode fieldArray, Locale locale,
            Map<String, String> fields) {
            for (final JsonNode fieldObject : fieldArray) {
                String zContactFieldName = null;
                if (fieldObject.has(DATE)) {
                    String type = "birthday";
                    if (fieldObject.has(TYPE)) {
                        type = fieldObject.get(TYPE).asText().toLowerCase();
                    }
                    zContactFieldName = StringUtils.defaultIfEmpty(DATE_FIELDS_MAP.get(type), type);
                    final JsonNode valueObject = fieldObject.get(DATE);
                    if (valueObject.isObject()) {
                        Integer year = null;
                        Integer month = null;
                        Integer day = null;
                        if (valueObject.has(YEAR)) {
                            year = valueObject.get(YEAR).asInt();
                        }
                        if (valueObject.has(MONTH)) {
                            month = valueObject.get(MONTH).asInt();
                        }
                        if (valueObject.has(DAY)) {
                            day = valueObject.get(DAY).asInt();
                        }
                        if (day == null || month == null) {
                            return;
                        }

                        final Calendar cal = Calendar.getInstance(locale);
                        if (year != null) {
                            cal.set(Calendar.YEAR, year);
                        }
                        if (month != null) {
                            cal.set(Calendar.MONTH, month - 1);
                        }
                        if (day != null) {
                            cal.set(Calendar.DAY_OF_MONTH, day);
                        }
                        final DateFormat df = DateFormat.getDateInstance(DateFormat.SHORT, locale);
                        final String dateString = df.format(cal.getTime());
                        fields.put(zContactFieldName, dateString);
                    }
                }
            }
        }

        /**
         * Fetches images from urls and creates attachments.
         *
         * @param fieldArray The json data containing the image urls
         * @param key The field key
         * @param attachments The list of attachments to add to
         */
        public static void parseImageField(JsonNode fieldArray, String key,
            List<Attachment> attachments) {
            int i = 1;
            for (final JsonNode fieldObject : fieldArray) {
                if (fieldObject.has(IMAGE_URL)) {
                    final String imageUrl = fieldObject.get(IMAGE_URL).asText();
                    if (!StringUtils.isEmpty(imageUrl)) {
                        try {
                            // fetch the image
                            final HttpGet get = new HttpGet(imageUrl);
                            final HttpResponseWrapper response = OAuth2Utilities.executeRequestRaw(get);
                            String imageNum = "";
                            if (i > 1) {
                                imageNum = String.valueOf(i++);
                            }
                            final String filename = String.format(
                                GoogleContactConstants.CONTACTS_IMAGE_NAME_TEMPLATE.getValue(), imageNum);
                            // add to attachments
                            final Attachment attachment = OAuth2Utilities
                                .createAttachmentFromResponse(response, key + imageNum, filename);
                            if (attachment != null) {
                                attachments.add(attachment);
                            }
                        } catch (ServiceException | IOException e) {
                            ZimbraLog.extensions
                                .debug("There was an issue fetching a contact image.");
                            // don't fail the rest
                        }
                    }
                }
            }
        }

        public static void parseAddressField(JsonNode fieldArray, Map<String, String> fields) {
            for (final JsonNode fieldObject : fieldArray) {
                if (fieldObject.isObject() && fieldObject.has(TYPE)) {
                    final String type = fieldObject.get(TYPE).asText();
                    Map<String, List<String>> targetMap = HOME_ADDRESS_FIELDS_MAP;
                    if (type != null) {
                        if (type.equalsIgnoreCase("work")) {
                            targetMap = WORK_ADDRESS_FIELDS_MAP;
                        } else if (type.equalsIgnoreCase("home")) {
                            targetMap = HOME_ADDRESS_FIELDS_MAP;
                        } else {
                            targetMap = OTHER_ADDRESS_FIELDS_MAP;
                        }
                    }
                    for (final String key : targetMap.keySet()) {
                        parseValuePart(fieldObject, targetMap.get(key), key, fields);
                    }
                }
            }
        }

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

        public static ParsedContact parseContact(JsonNode jsonContact, DataSource ds)
            throws ServiceException {
            final Map<String, String> contactFields = new HashMap<String, String>();
            final List<Attachment> attachments = new ArrayList<Attachment>();
            for (final GContactFieldType type : GContactFieldType.values()) {
                if (type != null) {
                    if (jsonContact.has(type.name())) {
                        final JsonNode fieldArray = jsonContact.get(type.name());
                        switch (type) {
                        case resourceName:
                            if (fieldArray.isTextual()) {
                                contactFields.put(GContactFieldType.resourceName.name(),
                                    fieldArray.asText());
                            }
                            break;
                        case addresses:
                            parseAddressField(fieldArray, contactFields);
                            break;
                        case emailAddresses:
                            parseTypedField(fieldArray, EMAIL_FIELDS_MAP, contactFields);
                            break;
                        case phoneNumbers:
                            parseTypedField(fieldArray, PHONE_FIELDS_MAP, contactFields);
                            break;
                        case birthdays:
                        case events:
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
                            parseDateField(fieldArray, locale, contactFields);
                            break;
                        case names:
                            parseMappingField(fieldArray, NAME_FIELDS_MAP, contactFields);
                            break;
                        case nicknames:
                            parseTypedField(fieldArray, NICKNAME_FIELDS_MAP, contactFields);
                            break;
                        case biographies:
                            parseSimpleField(fieldArray, A_notes, contactFields, true);
                            break;
                        case organizations:
                            parseMappingField(fieldArray, ORGANIZATIONS_FIELDS_MAP, contactFields);
                            break;
                        case urls:
                            parseTypedField(fieldArray, LINK_FIELDS_MAP, contactFields);
                            break;
                        case photos:
                            parseImageField(fieldArray, A_image, attachments);
                            break;
                        case userDefined:
                            parseKeyValueField(fieldArray, contactFields);
                            break;
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
