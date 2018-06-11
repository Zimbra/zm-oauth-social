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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import org.apache.commons.httpclient.methods.GetMethod;
import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZFolder.View;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

import org.apache.commons.lang.StringUtils;
/**
 * The FacebookOAuth2Handler class.<br>
 * Facebook OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */

public class FacebookOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

  /**
   * Contains the constants used in this implementation.
   */
  protected class FacebookConstants {

    /**
     * Invalid request error from Facebook.<br>
     * Protocol error, such as a invalid or missing required parameter.
     */
    protected class FacebookConstants {

        /**
         * Invalid request error from Facebook.<br>
         * Protocol error, such as a invalid or missing required parameter.
         */
        protected static final String RESPONSE_ERROR_INVALID_CODE = "100";

        /**
         * API Session.<br>
         * The login status or access token has expired,<br>
         * been revoked, or is otherwise invalid.
         */
        protected static final String RESPONSE_ERROR_SESSION_EXPIRED = "102";

        /**
         * API Unknown.<br>
         * Possibly a temporary issue due to downtime.<br>
         * Wait and retry the operation.<br>
         * If it occurs again, check you are requesting an existing API.
         */
        protected static final String RESPONSE_ERROR_API_UNKNOWN = "1";

        /**
         * API Service.<br>
         * Temporary issue due to downtime. Wait and retry the operation.
         */
        protected static final String RESPONSE_ERROR_API_SERVICE = "2";

        /**
         * API Too Many Calls.<br>
         * Temporary issue due to throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        protected static final String RESPONSE_ERROR_EXCESSIVE_CALLS = "4";

        /**
         * API User Too Many Calls.<br>
         * Temporary issue due to throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        protected static final String RESPONSE_ERROR_USER_EXCESSIVE_CALLS = "17";

        /**
         * API Permission Denied.<br>
         * Permission is either not granted or has been removed.
         */
        protected static final String RESPONSE_ERROR_PERM_DENIED = "10";

        /**
         * Access token has expired.<br>
         * Expired access token.
         */
        protected static final String RESPONSE_ERROR_TOKEN_EXPIRED = "190";

        /**
         * API Permission.<br>
         * Permission is either not granted or has been removed.
         */
        protected static final String RESPONSE_ERROR_PERMISSIONS_ERROR = "200-299";

        /**
         * Application limit reached.<br>
         * Temporary issue due to downtime or throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        protected static final String RESPONSE_ERROR_LIMIT_REACHED = "341";

        /**
         * Temporarily blocked for policies violations.<br>
         * Wait and retry the operation.
         */
        protected static final String RESPONSE_ERROR_POLICIES_VIOLATION = "368";

        /**
         * Too many requests.<br>
         * Picture profile URL rate-limit reached. Wait and retry the operation.
         */
        protected static final String RESPONSE_ERROR_TOO_MANY_REQUESTS = "429";

        /**
         * The authorize uri template for Facebook.
         */
        protected static final String AUTHORIZE_URI_TEMPLATE = "https://www.facebook.com/v3.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s";

        /**
         * The debug token uri, used to fetch the user_id from Facebook.
         */
        public static final String DEBUG_TOKEN_URI = "https://graph.facebook.com/debug_token";

        /**
         * The uri used to make backend call to fetch an access token.
         */
        public static final String AUTHENTICATE_URI = "https://graph.facebook.com/v3.0/oauth/access_token";

        /**
         * The scope required for Facebook.
         */
        protected static final String REQUIRED_SCOPES = "email";

        /**
         * The scope delimiter for Facebook.
         */
        protected static final String SCOPE_DELIMITER = ",";

        /**
         * The state parameter.
         */
        public static final String RELAY_KEY = "state";

        /**
         * The implementation name.
         */
        public static final String CLIENT_NAME = "facebook";

        /**
         * The implementation host.
         */
        public static final String HOST_FACEBOOK = "graph.facebook.com";

        /**
         * The contacts uri template.
         */
        public static final String CONTACTS_URI_TEMPLATE = "https://graph.facebook.com/v3.0/me/friends?access_token=%s&fields=%s&limit=%s";

        /**
        * The contacts pagination size for Facebook.
        */
        protected static final String CONTACTS_PAGE_SIZE = "100";

        /**
         * The refresh token code request uri template.<br>
         * Uses a code to request a fresh access token.
         */
        public static final String REFRESH_TOKEN_CODE_REQUEST_URI_TEMPLATE = "https://graph.facebook.com/oauth/client_code?access_token=%s&client_id=%s&client_secret=%s&redirect_uri=%s";

        /**
         * The access request uri template code, uses the existing, valid access token to fetch a code. 
         * This code will be used to request a fresh access token..
         */
        public static final String REFRESH_ACCESS_TOKEN_FOR_CODE_REQUEST_URI_TEMPLATE = "https://graph.facebook.com/oauth/access_token?client_id=%s&redirect_uri=%s&code=%s";

        /*
         * CSV list of data fields to import or limit the import to.
         * (Please note that this list may require permission scopes 
         * be added to the localconfig.xml for the related fields)
         */
        public static final String IMPORT_FIELDS_LIST = "email,address,name,location,birthday,about,gender,hometown,locale,first_name,middle_name,last_name";

    /**
     * API Session.<br>
     * The login status or access token has expired,<br>
     * been revoked, or is otherwise invalid.
     */
    protected static final String RESPONSE_ERROR_SESSION_EXPIRED = "102";

    /**
     * API Unknown.<br>
     * Possibly a temporary issue due to downtime.<br>
     * Wait and retry the operation.<br>
     * If it occurs again, check you are requesting an existing API.
     */
    public FacebookOAuth2Handler(Configuration config) {
        super(config, FacebookConstants.CLIENT_NAME, FacebookConstants.HOST_FACEBOOK);
        authenticateUri = FacebookConstants.AUTHENTICATE_URI;
        authorizeUriTemplate = FacebookConstants.AUTHORIZE_URI_TEMPLATE;
        requiredScopes = FacebookConstants.REQUIRED_SCOPES;
        scopeDelimiter = FacebookConstants.SCOPE_DELIMITER;
        relayKey = FacebookConstants.RELAY_KEY;
        // add associated import classes
        dataSource.addImportClass(View.contact.name(),
            FacebookContactsImport.class.getCanonicalName());
    }

    /**
     * API User Too Many Calls.<br>
     * Temporary issue due to throttling.<br>
     * Wait and retry the operation, or examine your API request volume.
     */
    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        final String clientId = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, client), client, account);
        final String clientSecret = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, client), client,
            account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, client), client,
            account);
        final String basicToken = OAuth2Utilities.encodeBasicHeader(clientId, clientSecret);
        // set client specific properties
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getTokenRequest(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateTokenResponse(credentials);
        // determine account associated with credentials
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get("access_token").asText());
        dataSource.syncDatasource(mailbox, oauthInfo);
        return true;
    }

    /**
     * API Permission Denied.<br>
     * Permission is either not granted or has been removed.
     */
    protected static final String RESPONSE_ERROR_PERM_DENIED = "10";

    /**
     * Access token has expired.<br>
     * Expired access token.
     */
    protected static final String RESPONSE_ERROR_TOKEN_EXPIRED = "190";

    /**
     * Retrieves the primary identifier of the user from the debug token uri.
     *
     * @param credentials The json containing an access_token
     * @param account The account to acquire configuration by access level
     * @return The unique user ID
     * @throws ServiceException If there are issues determining the primary
     *             address
     */
    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        JsonNode json = null;
        final String authToken = credentials.get("access_token").asText();
        String queryString;
        try {
            queryString = "?input_token=" + authToken + "&access_token="
                + URLEncoder.encode(getAppToken(account), OAuth2Constants.ENCODING);
        } catch (final UnsupportedEncodingException e) {
            throw ServiceException.PARSE_ERROR("Url encoding the social service app token failed.",
                e);
        }

        try {
            final GetMethod request = new GetMethod(FacebookConstants.DEBUG_TOKEN_URI);
            request.setQueryString(queryString);
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.warnQuietly("There was an issue acquiring the account details.",
                e);
            throw ServiceException.FAILURE("There was an issue acquiring the account details.",
                null);
        }

        final JsonNode data = json.get("data");
        if (data != null && data.has("user_id")) {
            return data.get("user_id").asText();
        }

        // if we couldn't retrieve the user id, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions
            .error("The user id could not be retrieved from the social service api.");
        throw ServiceException.UNSUPPORTED();
    }

    /**
     * Retrieves the App Token.
     *
     * @param account The account to acquire configuration by access level
     * @return The Facebook App token
     * @throws ServiceException If there was an issue with the request
     */
    protected String getAppToken(Account account) throws ServiceException {
        JsonNode json = null;
        final String url = FacebookConstants.AUTHENTICATE_URI;
        final String clientId = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, client), client, account);
        final String clientSecret = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, client), client,
            account);

        final String queryString = "?client_id=" + clientId + "&client_secret=" + clientSecret
            + "&grant_type=client_credentials";
        try {
            final GetMethod request = new GetMethod(url);
            request.setQueryString(queryString);
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.warnQuietly(
                "There was an issue acquiring the social service app access token.", e);
            throw ServiceException
                .FAILURE("There was an issue acquiring the social service app access token.", null);
        }

        if (json.has("access_token")) {
            return json.get("access_token").asText();
        }

        // if we couldn't retrieve the app token, the response from
        // downstream is missing data
        ZimbraLog.extensions.error("Unable to retrieve app token from social service api.");
        throw ServiceException.UNSUPPORTED();
    }

    final JsonNode data = json.get("data");
    if (data != null && data.has("user_id")) {
      return data.get("user_id").asText();
    }

    // if we couldn't retrieve the user id, the response from
    // downstream is missing data
    // this could be the result of a misconfigured application id/secret
    // (not enough scopes)
    ZimbraLog.extensions
            .error("The user id could not be retrieved from the social service api.");
    throw ServiceException.UNSUPPORTED();
  }

  /**
   * Retrieves the App Token.
   *
   * @return The Facebook App token
   * @throws ServiceException If there was an issue with the request
   */
  protected String getAppToken() throws ServiceException {
    JsonNode json = null;
    final String url = FacebookConstants.AUTHENTICATE_URI;
    final String queryString = "?client_id=" + this.clientId + "&client_secret="
        + this.clientSecret + "&grant_type=client_credentials";
    try {
      final GetMethod request = new GetMethod(url);
      request.setQueryString(queryString);
      json = executeRequestForJson(request);
    } catch (final IOException e) {
      ZimbraLog.extensions.warnQuietly(
          "There was an issue acquiring the social service app access token.", e);
      throw ServiceException
          .FAILURE("There was an issue acquiring the social service app access token.", null);
    }

    if (json.has("access_token")) {
      return json.get("access_token").asText();
    }

    // if we couldn't retrieve the app token, the response from
    // downstream is missing data
    ZimbraLog.extensions.error("Unable to retrieve app token from social service api.");
    throw ServiceException.UNSUPPORTED();
  }
}

