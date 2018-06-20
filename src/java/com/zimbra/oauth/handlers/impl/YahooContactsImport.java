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
import static com.zimbra.common.mailbox.ContactConstants.A_email;
import static com.zimbra.common.mailbox.ContactConstants.A_firstName;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCity;
import static com.zimbra.common.mailbox.ContactConstants.A_homeCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_homePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_homePhone2;
import static com.zimbra.common.mailbox.ContactConstants.A_homePostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_homeState;
import static com.zimbra.common.mailbox.ContactConstants.A_homeStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_homeURL;
import static com.zimbra.common.mailbox.ContactConstants.A_imAddress1;
import static com.zimbra.common.mailbox.ContactConstants.A_jobTitle;
import static com.zimbra.common.mailbox.ContactConstants.A_lastName;
import static com.zimbra.common.mailbox.ContactConstants.A_middleName;
import static com.zimbra.common.mailbox.ContactConstants.A_mobilePhone;
import static com.zimbra.common.mailbox.ContactConstants.A_namePrefix;
import static com.zimbra.common.mailbox.ContactConstants.A_nameSuffix;
import static com.zimbra.common.mailbox.ContactConstants.A_nickname;
import static com.zimbra.common.mailbox.ContactConstants.A_notes;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCity;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCustom1;
import static com.zimbra.common.mailbox.ContactConstants.A_otherPhone;
import static com.zimbra.common.mailbox.ContactConstants.A_otherPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_otherState;
import static com.zimbra.common.mailbox.ContactConstants.A_otherStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_otherURL;
import static com.zimbra.common.mailbox.ContactConstants.A_pager;
import static com.zimbra.common.mailbox.ContactConstants.A_workCity;
import static com.zimbra.common.mailbox.ContactConstants.A_workCountry;
import static com.zimbra.common.mailbox.ContactConstants.A_workEmail1;
import static com.zimbra.common.mailbox.ContactConstants.A_workFax;
import static com.zimbra.common.mailbox.ContactConstants.A_workPhone;
import static com.zimbra.common.mailbox.ContactConstants.A_workPhone2;
import static com.zimbra.common.mailbox.ContactConstants.A_workPostalCode;
import static com.zimbra.common.mailbox.ContactConstants.A_workState;
import static com.zimbra.common.mailbox.ContactConstants.A_workStreet;
import static com.zimbra.common.mailbox.ContactConstants.A_workURL;

import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.Pair;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.mailbox.Contact.Attachment;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.cs.service.mail.CreateContact;
import com.zimbra.cs.service.util.ItemId;
import com.zimbra.oauth.handlers.impl.YahooOAuth2Handler.YahooConstants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.oauth.utilities.OAuthDataSource;

/**
 * The YahooContactsImport class.<br>
 * Used to sync contacts from the Yahoo social service.<br>
 * Source from the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class YahooContactsImport implements DataImport {

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
    public YahooContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration.buildConfiguration(YahooConstants.CLIENT_NAME);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for yahoo: %s", e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    @Override
    public void test() throws ServiceException {
        final Pair<String, String> tokenAndGuid = refresh();
        String respContent = "";
        ParsedContact testContact = null;
        try {
            final String url = String.format(YahooConstants.CONTACTS_URI_TEMPLATE,
                tokenAndGuid.getSecond(), "json", 10);
            final String authorizationHeader = String.format("Bearer %s", tokenAndGuid.getFirst());
            final JsonNode jsonResponse = getContactsRequest(url, authorizationHeader);
            respContent = jsonResponse.toString();
            if (jsonResponse != null && jsonResponse.isObject()) {
                if (jsonResponse.has("contacts") && jsonResponse.get("contacts").isObject()) {
                    final JsonNode contactsObject = jsonResponse.get("contacts");
                    if (contactsObject.has("contact") && contactsObject.get("contact").isArray()) {
                        final JsonNode jsonContacts = contactsObject.get("contact");
                        for (final JsonNode contactElement : jsonContacts) {
                            final ParsedContact contact = YahooContactsUtil
                                .parseYContact(contactElement, mDataSource);
                            if (contact != null) {
                                testContact = contact;
                                break;
                            }
                        }
                    } else {
                        ZimbraLog.extensions
                            .debug("Did not find 'contact' element in 'contacts' object");
                    }
                } else {
                    ZimbraLog.extensions
                        .debug("Did not find 'contacts' element in JSON response object");
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object");
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(
                "Data source test failed. Failed to fetch contacts from  Yahoo Contacts API for testing",
                e);
        }
        if (testContact == null) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from  Yahoo Contacts API for testing. Response status code %d. Response status line: %s. Response body %s",
                respContent), null);
        }
    }

    /**
     * Retrieves the Yahoo user accessToken and guid.
     *
     * @return Pair of accessToken and guid
     * @throws ServiceException If there are issues
     */
    protected Pair<String, String> refresh() throws ServiceException {
        Account acct = this.mDataSource.getAccount();
        final OAuthInfo oauthInfo = new OAuthInfo(new HashMap<String, String>());
        final String refreshToken = OAuthDataSource.getRefreshToken(mDataSource);
        final String clientId = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, YahooConstants.CLIENT_NAME), YahooConstants.CLIENT_NAME, acct);
        final String clientSecret = config.getString(String
            .format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, YahooConstants.CLIENT_NAME), YahooConstants.CLIENT_NAME, acct);
        final String clientRedirectUri = config.getString(String.format(
            OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, YahooConstants.CLIENT_NAME), YahooConstants.CLIENT_NAME, acct);

        // set client specific properties
        oauthInfo.setRefreshToken(refreshToken);
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(YahooConstants.AUTHENTICATE_URI);

        ZimbraLog.extensions.debug("Fetching access credentials for import.");
        final JsonNode credentials = YahooOAuth2Handler.getTokenRequest(oauthInfo,
            OAuth2Utilities.encodeBasicHeader(clientId, clientSecret));

        return new Pair<String, String>(credentials.get("access_token").asText(),
            credentials.get(YahooConstants.GUID_KEY).asText());
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
        final GetMethod get = new GetMethod(url);
        get.addRequestHeader(OAuth2Constants.HEADER_AUTHORIZATION, authorizationHeader);
        ZimbraLog.extensions.debug("Fetching contacts for import.");
        return OAuth2Handler.executeRequestForJson(get);
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        final Pair<String, String> tokenAndGuid = refresh();
        final String[] attrs = mDataSource.getMultiAttr(Provisioning.A_zimbraDataSourceAttribute);
        int rev = 0;
        if (attrs.length > 0) {
            final String val = attrs[0];
            try {
                final Integer revision = Integer.parseInt(val);
                if (revision != null) {
                    rev = revision.intValue();
                }
            } catch (final NumberFormatException e) {
                throw ServiceException.FAILURE(
                    String.format("Invalid value in zimbraDataSourceAttribute: %s", val), e);
            }
        }
        String respContent = "";
        try {
            final String url = String.format(YahooConstants.CONTACTS_URI_TEMPLATE,
                tokenAndGuid.getSecond(), "json", rev);
            final String authorizationHeader = String.format("Bearer %s", tokenAndGuid.getFirst());
            // log this only at the most verbose level, because this contains
            // privileged information
            ZimbraLog.extensions.trace(
                "Attempting to sync Yahoo contacts. URL: %s. authorizationHeader: %s", url,
                authorizationHeader);
            final JsonNode jsonResponse = getContactsRequest(url, authorizationHeader);
            respContent = jsonResponse.toString();
            // log this only at the most verbose level, because this contains
            // privileged information
            ZimbraLog.extensions.trace("contacts sync response from Yahoo %s", respContent);
            if (jsonResponse != null && jsonResponse.isContainerNode()) {
                if (jsonResponse.has("contactsync")
                    && jsonResponse.get("contactsync").isContainerNode()) {
                    final JsonNode contactsObject = jsonResponse.get("contactsync");
                    if (contactsObject.has("contacts")
                        && contactsObject.get("contacts").isArray()) {
                        final JsonNode jsonContacts = contactsObject.get("contacts");
                        final List<ParsedContact> clist = new ArrayList<ParsedContact>();
                        ZimbraLog.extensions
                            .debug("Cycling through list to determine new contacts to add.");
                        for (final JsonNode contactElement : jsonContacts) {
                            if (contactElement.isObject() && contactElement.has("op")) {
                                final String op = contactElement.get("op").asText();
                                if ("add".equalsIgnoreCase(op)) {
                                    final ParsedContact contact = YahooContactsUtil
                                        .parseYContact(contactElement, mDataSource);
                                    if (contact != null) {
                                        clist.add(contact);
                                    }
                                }
                            }
                        }
                        if (!clist.isEmpty()) {
                            final ItemId iidFolder = new ItemId(mDataSource.getMailbox(),
                                mDataSource.getFolderId());
                            ZimbraLog.extensions.debug("Creating contacts from parsed list.");
                            CreateContact.createContacts(null, mDataSource.getMailbox(), iidFolder,
                                clist, null);
                        }
                    } else {
                        ZimbraLog.extensions
                            .debug("Did not find 'contacts' element in 'contactsync' object");
                    }
                    if (contactsObject.has("rev")) {
                        rev = contactsObject.get("rev").asInt();
                        final Map<String, Object> dsAttrs = new HashMap<String, Object>();
                        dsAttrs.put(Provisioning.A_zimbraDataSourceAttribute, rev);
                        Provisioning.getInstance().modifyDataSource(mDataSource.getAccount(),
                            mDataSource.getId(), dsAttrs);
                    } else {
                        ZimbraLog.extensions.debug(
                            "Did not find 'rev' element in 'contactsync' object. Response body: %s",
                            respContent);
                    }
                } else {
                    ZimbraLog.extensions.debug(
                        "Did not find 'contactsync' element in JSON response object. Response body: %s",
                        respContent);
                }
            } else {
                ZimbraLog.extensions.debug("Did not find JSON response object. Response body: %s",
                    respContent);
            }
        } catch (UnsupportedOperationException | IOException e) {
            throw ServiceException.FAILURE(String.format(
                "Data source test failed. Failed to fetch contacts from  Yahoo Contacts API for testing. Response body: %s",
                respContent), e);
        }
    }

    /**
     * The YahooContactsUtil class.<br>
     * Used to parse contacts from the Yahoo social service.<br>
     * Source from the original YahooContactsUtil class by @author Greg Solovyev.
     *
     * @author Zimbra API Team
     * @package com.zimbra.oauth.handlers.impl
     * @copyright Copyright © 2018
     */
    @SuppressWarnings("serial")
    public static class YahooContactsUtil {

        static enum YContactFieldType {
            guid,
            nickname,
            email,
            yahooid,
            otherid,
            phone,
            jobTitle,
            company,
            notes,
            link,
            custom,
            name,
            address,
            birthday,
            anniversary,
            jobtitle,
            image
        }

        // parts of contact JSON object
        public static final String VALUE = "value";
        public static final String TYPE = "type";
        public static final String FLAGS = "flags";
        public static final String FIELDS = "fields";

        // yahoo name field value parts
        public static final String GIVENNAME = "givenName";
        public static final String MIDDLE = "middleName";
        public static final String FAMILYNAME = "familyName";
        public static final String PREFIX = "prefix";
        public static final String SUFFIX = "suffix";

        public static final Map<String, String> NAME_FIELDS_MAP = new HashMap<String, String>() {

            {
                put(A_firstName, GIVENNAME);
                put(A_middleName, MIDDLE);
                put(A_lastName, FAMILYNAME);
                put(A_namePrefix, PREFIX);
                put(A_nameSuffix, SUFFIX);
            }
        };

        // yahoo address field value parts
        public static final String STREET = "street";
        public static final String CITY = "city";
        public static final String STATE = "stateOrProvince";
        public static final String POSTALCODE = "postalCode";
        public static final String COUNTRY = "country";
        public static final String COUNTRYCODE = "countryCode";
        public static final Map<String, List<String>> WORK_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_workStreet, Arrays.asList(STREET));
                put(A_workCity, Arrays.asList(CITY));
                put(A_workState, Arrays.asList(STATE));
                put(A_workPostalCode, Arrays.asList(POSTALCODE));
                put(A_workCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        public static final Map<String, List<String>> HOME_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_homeStreet, Arrays.asList(STREET));
                put(A_homeCity, Arrays.asList(CITY));
                put(A_homeState, Arrays.asList(STATE));
                put(A_homePostalCode, Arrays.asList(POSTALCODE));
                put(A_homeCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        public static final Map<String, List<String>> OTHER_ADDRESS_FIELDS_MAP = new HashMap<String, List<String>>() {

            {
                put(A_otherStreet, Arrays.asList(STREET));
                put(A_otherCity, Arrays.asList(CITY));
                put(A_otherState, Arrays.asList(STATE));
                put(A_otherPostalCode, Arrays.asList(POSTALCODE));
                put(A_otherCountry, Arrays.asList(COUNTRY, COUNTRYCODE));
            }
        };
        // yahoo date field value parts
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
                put("personal", A_homePhone);
                put("work", A_workPhone);
                put("mobile", A_mobilePhone);
                put("other", A_otherPhone);
                put("pager", A_pager);
                put("fax", A_workFax);
                put("yahoophone", A_homePhone2);
                put("external", A_workPhone2);
            }
        };
        public static final Map<String, String> EMAIL_FIELDS_MAP = new HashMap<String, String>() {

            {
                put("personal", A_email);
                put("home", A_email);
                put("work", A_workEmail1);
            }
        };
        public static final Map<String, String> LINK_FIELDS_MAP = new HashMap<String, String>() {

            {
                put("personal", A_homeURL);
                put("home", A_homeURL);
                put("work", A_workURL);
                put("other", A_otherURL);
            }
        };
        public static final String IMAGE_URL = "imageUrl";

        public static void parseSimpleField(JsonNode fieldObject, String key,
            Map<String, String> fields) {
            if (fieldObject.has(VALUE)) {
                String zContactFieldName = key;
                final String value = fieldObject.get(VALUE).asText();
                if (value != null && !value.isEmpty()) {
                    int i = 1;
                    final String tmpName = zContactFieldName.replace("1", "");
                    while (fields.containsKey(zContactFieldName)) {
                        i++;
                        zContactFieldName = String.format("%s%d", tmpName, i);
                    }
                    fields.put(zContactFieldName, value);
                }
            }
        }

        public static void parseFlaggedField(JsonNode fieldObject, String defaultFieldName,
            Map<String, String> flagMap, Map<String, String> fields) {
            if (fieldObject.has(VALUE)) {
                String zContactFieldName = null;
                if (fieldObject.has(FLAGS)) {
                    final JsonNode flagsArray = fieldObject.get(FLAGS);
                    if (flagsArray.isArray()) {
                        if (flagsArray.size() > 0) {
                            final String fieldFlag = flagsArray.get(0).asText().toLowerCase();
                            zContactFieldName = flagMap.get(fieldFlag);
                        }
                    }
                }

                if (zContactFieldName == null) {
                    zContactFieldName = defaultFieldName;
                }
                final JsonNode valueElement = fieldObject.get(VALUE);
                if (valueElement != null) {
                    int i = 1;
                    final String tmpName = zContactFieldName.replace("1", "");
                    while (fields.containsKey(zContactFieldName)) {
                        i++;
                        zContactFieldName = String.format("%s%d", tmpName, i);
                    }
                    fields.put(zContactFieldName, valueElement.asText());
                }
            }
        }

        public static void parseDateField(JsonNode fieldObject, Locale locale,
            Map<String, String> fields) {
            String zContactFieldName = null;
            if (fieldObject.has(VALUE)) {
                zContactFieldName = DATE_FIELDS_MAP
                    .get(fieldObject.get(TYPE).asText().toLowerCase());
                if (zContactFieldName != null) {
                    final JsonNode valueObject = fieldObject.get(VALUE);
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

        public static void parseNameField(JsonNode fieldObject, Map<String, String> fields) {
            if (fieldObject.has(VALUE)) {
                final JsonNode valueObject = fieldObject.get(VALUE);
                if (valueObject.isObject()) {
                    for (final String key : NAME_FIELDS_MAP.keySet()) {
                        parseValuePart(valueObject, NAME_FIELDS_MAP.get(key), key, fields);
                    }
                }
            }
        }

        /**
         * Fetches an image from url and creates an attachment.
         *
         * @param fieldObject The json data containing the image url
         * @param key The field key
         * @param attachments The list of attachments to add to
         */
        public static void parseImageField(JsonNode fieldObject, String key,
            List<Attachment> attachments) {
            if (fieldObject.has(VALUE)) {
                final JsonNode valueObject = fieldObject.get(VALUE);
                if (valueObject.isObject() && valueObject.has(IMAGE_URL)) {
                    final String imageUrl = valueObject.get(IMAGE_URL).asText();
                    if (!StringUtils.isEmpty(imageUrl)) {
                        try {
                            // fetch the image
                            final GetMethod get = new GetMethod(imageUrl);
                            OAuth2Handler.executeRequest(get);
                            // add to attachments
                            final Attachment attachment = OAuth2Utilities
                                .createAttachmentFromResponse(get, key,
                                    YahooConstants.CONTACTS_IMAGE_NAME);
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

        public static void parseAddressField(JsonNode fieldObject, Map<String, String> fields) {
            String addressFlag = null;
            if (fieldObject.has(FLAGS)) {
                final JsonNode flagsArray = fieldObject.get(FLAGS);
                if (flagsArray.isArray()) {
                    if (flagsArray.size() > 0) {
                        addressFlag = flagsArray.get(0).asText().toLowerCase();
                    }
                }
            }
            if (fieldObject.has(VALUE)) {
                final JsonNode valueObject = fieldObject.get(VALUE);
                if (valueObject.isObject()) {
                    Map<String, List<String>> targetMap = HOME_ADDRESS_FIELDS_MAP;
                    if (addressFlag != null) {
                        if (addressFlag.equalsIgnoreCase("work")) {
                            targetMap = WORK_ADDRESS_FIELDS_MAP;
                        } else if (addressFlag.equalsIgnoreCase("home")) {
                            targetMap = HOME_ADDRESS_FIELDS_MAP;
                        } else {
                            targetMap = OTHER_ADDRESS_FIELDS_MAP;
                        }
                    }
                    for (final String key : targetMap.keySet()) {
                        parseValuePart(valueObject, targetMap.get(key), key, fields);
                    }
                }
            }
        }

        public static void parseValuePart(JsonNode valueObject, String partName, String fieldName,
            Map<String, String> fields) {
            if (valueObject.has(partName)) {
                final JsonNode tmp = valueObject.get(partName);
                if (tmp != null) {
                    final String szValue = tmp.asText();
                    if (szValue != null && !szValue.isEmpty()) {
                        fields.put(fieldName, szValue);
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

        public static ParsedContact parseYContact(JsonNode jsonContact, DataSource ds)
            throws ServiceException {
            final Map<String, String> contactFields = new HashMap<String, String>();
            // will contain attachments in future iterations - assuming API support
            final List<Attachment> attachments = new ArrayList<Attachment>();
            if (jsonContact.has(FIELDS)) {
                final JsonNode jsonFields = jsonContact.get(FIELDS);
                if (jsonFields.isArray()) {
                    final Iterator<JsonNode> iter = jsonFields.iterator();
                    while (iter.hasNext()) {
                        final JsonNode fieldObj = iter.next();
                        if (fieldObj.isObject()) {
                            if (fieldObj.has(TYPE) && fieldObj.has(VALUE)) {
                                final String fieldType = fieldObj.get(TYPE).asText().toLowerCase();
                                YahooContactsUtil.YContactFieldType type = null;
                                if (fieldType != null && !fieldType.isEmpty()) {
                                    try {
                                        type = YahooContactsUtil.YContactFieldType
                                            .valueOf(fieldType);
                                    } catch (final Exception e) {
                                        ZimbraLog.extensions.debug(
                                            "YahooContactsUtil cannot map Yahoo Contact field of type '%s' to any knwon contact field.",
                                            fieldType);
                                    }
                                }
                                if (type != null) {
                                    switch (type) {
                                    case email:
                                        parseFlaggedField(fieldObj, A_email, EMAIL_FIELDS_MAP,
                                            contactFields);
                                        break;
                                    case phone:
                                        parseFlaggedField(fieldObj, A_homePhone, PHONE_FIELDS_MAP,
                                            contactFields);
                                        break;
                                    case address:
                                        parseAddressField(fieldObj, contactFields);
                                        break;
                                    case birthday:
                                    case anniversary:
                                        Locale locale = null;
                                        if (ds != null) {
                                            locale = ds.getAccount().getLocale();
                                        }
                                        if (locale == null) {
                                            try {
                                                locale = Provisioning.getInstance().getConfig()
                                                    .getLocale();
                                            } catch (final Exception e) {
                                                ZimbraLog.extensions.warn(
                                                    "Failed to get locale while parsing a contact");
                                            }
                                        }
                                        if (locale == null) {
                                            locale = Locale.US;
                                        }
                                        parseDateField(fieldObj, locale, contactFields);
                                        break;
                                    case name:
                                        parseNameField(fieldObj, contactFields);
                                        break;
                                    case company:
                                        parseSimpleField(fieldObj, A_company, contactFields);
                                        break;
                                    case notes:
                                        parseSimpleField(fieldObj, A_notes, contactFields);
                                        break;
                                    case nickname:
                                        parseSimpleField(fieldObj, A_nickname, contactFields);
                                        break;
                                    case jobTitle:
                                        parseSimpleField(fieldObj, A_jobTitle, contactFields);
                                        break;
                                    case link:
                                        parseFlaggedField(fieldObj, A_homeURL, LINK_FIELDS_MAP,
                                            contactFields);
                                        break;
                                    case yahooid:
                                        parseSimpleField(fieldObj, A_imAddress1, contactFields);
                                        break;
                                    case jobtitle:
                                        parseSimpleField(fieldObj, A_jobTitle, contactFields);
                                        break;
                                    case image:
                                        break;
                                    default:
                                        parseSimpleField(fieldObj, A_otherCustom1, contactFields);
                                        break;
                                    }
                                } else {
                                    parseSimpleField(fieldObj, fieldType, contactFields);
                                }
                            }
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
