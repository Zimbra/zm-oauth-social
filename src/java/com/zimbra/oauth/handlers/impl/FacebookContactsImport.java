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
import static com.zimbra.common.mailbox.ContactConstants.A_homeCity;
import static com.zimbra.common.mailbox.ContactConstants.A_imAddress1;
import static com.zimbra.common.mailbox.ContactConstants.A_lastName;
import static com.zimbra.common.mailbox.ContactConstants.A_middleName;
import static com.zimbra.common.mailbox.ContactConstants.A_otherCustom1;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.cs.service.mail.CreateContact;
import com.zimbra.cs.service.util.ItemId;
import com.zimbra.oauth.handlers.impl.FacebookOAuth2Handler.FacebookConstants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.oauth.utilities.OAuthDataSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.methods.GetMethod;

/**
 * @author zimbra
 *
 */
public class FacebookContactsImport implements DataImport {

  /**
   * The datasource under import.
   */
  private final DataSource mDataSource;


  /**
   * Configuration wrapper.
   */
  private final Configuration config = Configuration.getDefaultConfiguration();

  /**
   * Constructor.
   *
   * @param datasource The datasource to set
   */
  public FacebookContactsImport(DataSource datasource) {
    mDataSource = datasource;
  }


  @Override
  public void test() {

  }
  

  /**
   * Retrieves the Facebook user accessToken.
   *
   * @return accessToken
   * @throws ServiceException If there are issues
   */
  protected String refresh() throws ServiceException {
    final OAuthInfo oauthInfo = new OAuthInfo(new HashMap<String, String>());
    final String refreshToken = OAuthDataSource.getRefreshToken(mDataSource);
    final String clientId = config.getString(
        String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, FacebookConstants.CLIENT_NAME));
    final String clientSecret = config.getString(String
        .format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, FacebookConstants.CLIENT_NAME));
    final String clientRedirectUri = config.getString(String.format(
        OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, FacebookConstants.CLIENT_NAME));

    // set client specific properties
    oauthInfo.setRefreshToken(refreshToken);
    oauthInfo.setClientId(clientId);
    oauthInfo.setClientSecret(clientSecret);
    oauthInfo.setClientRedirectUri(clientRedirectUri);
    oauthInfo.setTokenUrl(FacebookConstants.AUTHENTICATE_URI);

    ZimbraLog.extensions.debug("Fetching access credentials for import.");
    final JsonNode credentials = FacebookOAuth2Handler.getTokenRequest(oauthInfo,
        OAuth2Utilities.encodeBasicHeader(clientId, clientSecret));

    return credentials.get("access_token").asText();
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
    ZimbraLog.extensions.debug("Fetching contacts for import.");
    return OAuth2Handler.executeRequestForJson(get);
  }

  @Override
  public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
    final String tokenAndGuid = refresh();
    String respContent = "";
    String fieldsCsv = "email,address,name,location,birthday,about,gender,hometown,locale,"
        + "first_name";
    try {
      final String url = String.format(FacebookConstants.CONTACTS_URI_TEMPLATE, tokenAndGuid,
          fieldsCsv);
      // log this only at the most verbose level, because this contains
      // privileged information
      ZimbraLog.extensions.trace(
          "Attempting to sync Facebook contacts. URL: %s", url);
      final JsonNode jsonResponse = getContactsRequest(url);
      respContent = jsonResponse.toString();
      // log this only at the most verbose level, because this contains
      // privileged information
      ZimbraLog.extensions.trace("contacts sync response from Facebook %s", respContent);
      if (jsonResponse != null && jsonResponse.isContainerNode()) {
        if (jsonResponse.has("data")
            && jsonResponse.get("data").isContainerNode()) {
          final JsonNode contactsObject = jsonResponse.get("data");
          final List<ParsedContact> clist = new ArrayList<ParsedContact>();
          ZimbraLog.extensions.debug("Cycling through list to determine new contacts to add.");
          for (final JsonNode contactElement : contactsObject) {
            if (contactElement.isObject() && contactElement.has("id")) {
              final String id = contactElement.get("id").asText();
              if (!id.isEmpty()) {
                final ParsedContact contact = FacebookContactsUtil
                    .parseFContact(contactElement, mDataSource);
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
          .debug("Did not find 'data' element in json object");
        }
      } else {
        ZimbraLog.extensions.debug("Did not find JSON response object. Response body: %s",
            respContent);
      }
    } catch (UnsupportedOperationException | IOException e) {
      throw ServiceException.FAILURE(String.format(
        "Data source test failed. Failed to fetch contacts from Facebook Contacts API"
          + "for testing. Response body: %s",
        respContent), e);
    }
  }

  /**
   * The FacebookContactsUtil class.<br>
   * Used to parse contacts from the Facebook service.<br>
   * Source from the original YahooContactsUtil class by @author Greg Solovyev.
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

    public static final Map<String, String> NAME_FIELDS_MAP = new HashMap<String, String>() {
        {
          put(A_firstName, GIVENNAME);
          put(A_middleName, MIDDLE);
          put(A_lastName, FAMILYNAME);
        }
    };


    /**
     * Parser for name field.
     * 
     * @param fieldObject JSON object
     * @param fields Map of fields
     */
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
     * Parses the value into a map.
     * 
     * @param valueObject JSON object
     * @param partName Name to fetch value data
     * @param fieldName The field name to map the value to 
     * @param fields the map of fields to populate
     */
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

    /**
     * Parses the fields and adds key (with trailing incrementing number, if key exists)
     * as the key, with the value of the node. 
     * 
     * @param fieldObject JSON node
     * @param key Key name
     * @param fields Map of fields
     */
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

    /**
     * Parse the contact from JSON node. 
     * 
     * @param jsonContact JSON node containing contact data
     * @param ds DataSource object
     * @return Parsed contact data
     * @throws ServiceException If there was an error parsing the JSON data
     */
    public static ParsedContact parseFContact(JsonNode jsonContact, DataSource ds)
        throws ServiceException {
      final Map<String, String> contactFields = new HashMap<String, String>();
      if (jsonContact.has(FIELDS)) {
        final JsonNode jsonFields = jsonContact.get(FIELDS);
        if (jsonFields.isArray()) {
          final Iterator<JsonNode> iter = jsonFields.iterator();
          while (iter.hasNext()) {
            final JsonNode fieldObj = iter.next();
            if (fieldObj.isObject()) {
              if (fieldObj.has(TYPE) && fieldObj.has(VALUE)) {
                final String fieldType = fieldObj.get(TYPE).asText().toLowerCase();
                FacebookContactsUtil.FContactFieldType type = null;
                if (fieldType != null && !fieldType.isEmpty()) {
                  try {
                    type = FacebookContactsUtil.FContactFieldType
                        .valueOf(fieldType);
                  } catch (final Exception e) {
                    ZimbraLog.extensions.debug(
                        "FacebookContactsUtil cannot map Facebook Contact field of type '%s' "
                        + "to any knwon contact field.",
                        fieldType);
                  }
                  if (type != null) {
                    switch (type) {
                      case id:
                        parseSimpleField(fieldObj, A_imAddress1, contactFields);
                        break;
                      case name:
                        parseNameField(fieldObj, contactFields);
                        break;
                      default:
                        parseSimpleField(fieldObj, A_otherCustom1, contactFields);
                        break;
                    }
                  }
                }
              }
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
