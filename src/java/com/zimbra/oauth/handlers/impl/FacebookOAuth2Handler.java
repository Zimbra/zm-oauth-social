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

import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.soap.admin.type.DataSourceType;

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
     * Contains error constants used in this implementation.
     */
    protected enum FacebookErrorConstants {

        /**
         * Invalid request error from Facebook.<br>
         * Protocol error, such as a invalid or missing required parameter.
         */
        RESPONSE_ERROR_INVALID_CODE("100"),

        /**
         * API Session.<br>
         * The login status or access token has expired,<br>
         * been revoked, or is otherwise invalid.
         */
        RESPONSE_ERROR_SESSION_EXPIRED("102"),

        /**
         * API Unknown.<br>
         * Possibly a temporary issue due to downtime.<br>
         * Wait and retry the operation.<br>
         * If it occurs again, check you are requesting an existing API.
         */
        RESPONSE_ERROR_API_UNKNOWN("1"),

        /**
         * API Service.<br>
         * Temporary issue due to downtime. Wait and retry the operation.
         */
        RESPONSE_ERROR_API_SERVICE("2"),

        /**
         * API Too Many Calls.<br>
         * Temporary issue due to throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        RESPONSE_ERROR_EXCESSIVE_CALLS("4"),

        /**
         * API User Too Many Calls.<br>
         * Temporary issue due to throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        RESPONSE_ERROR_USER_EXCESSIVE_CALLS("17"),

        /**
         * API Permission Denied.<br>
         * Permission is either not granted or has been removed.
         */
        RESPONSE_ERROR_PERM_DENIED("10"),

        /**
         * Access token has expired.<br>
         * Expired access token.
         */
        RESPONSE_ERROR_TOKEN_EXPIRED("190"),

        /**
         * API Permission.<br>
         * Permission is either not granted or has been removed.
         */
        RESPONSE_ERROR_PERMISSIONS_ERROR("200-299"),

        /**
         * Application limit reached.<br>
         * Temporary issue due to downtime or throttling.<br>
         * Wait and retry the operation, or examine your API request volume.
         */
        RESPONSE_ERROR_LIMIT_REACHED("341"),

        /**
         * Temporarily blocked for policies violations.<br>
         * Wait and retry the operation.
         */
        RESPONSE_ERROR_POLICIES_VIOLATION("368"),

        /**
         * Too many requests.<br>
         * Picture profile URL rate-limit reached. Wait and retry the operation.
         */
        RESPONSE_ERROR_TOO_MANY_REQUESTS("429"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("DEFAULT_ERROR");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private FacebookErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static FacebookErrorConstants fromString(String code) {
            for (final FacebookErrorConstants t : FacebookErrorConstants.values()) {
                if (StringUtils.equals(t.getValue(), code)) {
                    return t;
                }
            }
            return DEFAULT_ERROR;
        }

    }

    /**
     * Contains contact constants used in this implementation.
     */
    protected enum FacebookContactConstants {

        /**
         * The contacts uri template.
         *
         * CSV list of data fields to import or limit the import to.
         * (Please note that this list may require permission scopes
         * be added to the localconfig.xml for the related fields)
         */
        CONTACTS_URI_TEMPLATE("https://graph.facebook.com/v3.0/me/friends?access_token=%s&fields=email,address,name,location,birthday,about,gender,hometown,locale,first_name,middle_name,last_name&limit=%s"),

        /**
        * The contacts pagination size for Facebook.
        */
        CONTACTS_PAGE_SIZE("100");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private FacebookContactConstants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum FacebookOAuth2Constants {

        /**
         * The authorize uri template for Facebook.
         */
        AUTHORIZE_URI_TEMPLATE("https://www.facebook.com/v3.0/dialog/oauth?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The user details uri, used to fetch the authorized OAuth user details from Facebook.
         */
        USER_DETAILS_URI_TEMPLATE("https://graph.facebook.com/me?access_token=%s&fields=first_name,middle_name,last_name,email"),

        /**
         * The uri used to make backend call to fetch an access token.
         */
        AUTHENTICATE_URI("https://graph.facebook.com/v3.0/oauth/access_token"),

        /**
         * The scope required for Facebook.
         */
        REQUIRED_SCOPES("email"),

        /**
         * The scope delimiter to use.
         */
        SCOPE_DELIMITER(","),

        /**
         * The state parameter.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("facebook"),

        /**
         * The implementation host.
         */
        HOST_FACEBOOK("graph.facebook.com"),

        /**
         * The refresh token code request uri template.<br>
         * Uses a code to request a fresh access token.
         */
        REFRESH_TOKEN_CODE_REQUEST_URI_TEMPLATE("https://graph.facebook.com/oauth/client_code?access_token=%s&client_id=%s&client_secret=%s&redirect_uri=%s"),

        /**
         * The access request uri template code, uses the existing, valid access token
         * to fetch a code.
         * This code will be used to request a fresh access token.
         */
        REFRESH_ACCESS_TOKEN_FOR_CODE_REQUEST_URI_TEMPLATE("https://graph.facebook.com/oauth/access_token?client_id=%s&redirect_uri=%s&code=%s");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private FacebookOAuth2Constants(String constant) {
            this.constant = constant;
        }
    }

    /**
     * Constructs an FacebookOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public FacebookOAuth2Handler(Configuration config) {
        super(config, FacebookOAuth2Constants.CLIENT_NAME.getValue(),
            FacebookOAuth2Constants.HOST_FACEBOOK.getValue());
        authenticateUri = FacebookOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = FacebookOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = FacebookOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = FacebookOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = FacebookOAuth2Constants.RELAY_KEY.getValue();
        dataSource.addImportClass(DataSourceType.oauth2contact.name(),
            FacebookContactsImport.class.getCanonicalName());
    }

    /**
     * Facebook authenticate handler.
     *
     * @throws ServiceException Thrown if an error was encountered
     * @see IOAuth2Handler#authenticate(OAuthInfo)
     */
    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        final String clientId = oauthInfo.getClientId();
        final String clientSecret = oauthInfo.getClientSecret();
        final String basicToken = OAuth2Utilities.encodeBasicHeader(clientId, clientSecret);
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getTokenRequest(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateTokenResponse(credentials);
        // determine account associated with credentials
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken(), account);

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get("access_token").asText());
        dataSource.syncDatasource(mailbox, oauthInfo, null);
        return true;
    }

    /**
     * Validates that the response from authenticate has no errors, and contains
     * the requested access information.
     *
     * @param response The json response from authenticate
     * @throws ServiceException OPERATION_DENIED If the refresh token was deemed
     *     invalid, or incorrect redirect uri.<br>
     *     If the client id or client secret are incorrect.<br>
     *     PARSE_ERROR If the response from Google has no errors, but
     *     the access info is missing.<br>
     *     PERM_DENIED If the refresh token or code is expired, or for
     *     general rejection.<br>
     *     INVALID_REQUEST If the request parameters are invalid.<br>
     *     TEMPORARILY_UNAVAILABLE If there was an issue with the FB
     *     OAuth server.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final JsonNode errorDetails = response.get("error");
            String errorCode = errorDetails.get("code").asText();
            final String errorMsg = errorDetails.get("message").asText();

            errorCode = inErrorCodeRange(errorCode);

            switch (FacebookErrorConstants.fromString(errorCode)) {
                case RESPONSE_ERROR_INVALID_CODE:
                    ZimbraLog.extensions.debug("Invalid request error from Facebook: "
                        + errorMsg);
                    throw ServiceException.INVALID_REQUEST(
                            "The authentication " + "request parameters are invalid.", null);
                case RESPONSE_ERROR_SESSION_EXPIRED:
                    ZimbraLog.extensions.debug("API Session error: " + errorMsg);
                    throw ServiceException.OPERATION_DENIED("The login status or "
                            + "access token has expired, been revoked, or is otherwise invalid.");
                case RESPONSE_ERROR_API_UNKNOWN:
                    ZimbraLog.extensions.debug("API Unknown: " + errorMsg);
                    throw ServiceException.OPERATION_DENIED("API Unknown. Possibly a temporary "
                            + "issue due to downtime. If it occurs again, check you are "
                            + "requesting an existing API.");
                case RESPONSE_ERROR_API_SERVICE:
                    ZimbraLog.extensions.debug("API Service issue: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_EXCESSIVE_CALLS:
                    ZimbraLog.extensions.debug("Too Many Calls: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_USER_EXCESSIVE_CALLS:
                    ZimbraLog.extensions.debug("User, Too Many Calls: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_TOKEN_EXPIRED:
                    ZimbraLog.extensions.debug("Access token has expired: " + errorMsg);
                    throw ServiceException.OPERATION_DENIED("Expired access token.");
                case RESPONSE_ERROR_PERM_DENIED:
                case RESPONSE_ERROR_PERMISSIONS_ERROR:
                    ZimbraLog.extensions.debug("API Permissions issue: " + errorMsg);
                    throw ServiceException
                            .PERM_DENIED("Permission is either not granted or has "
                                + "been removed.");
                case RESPONSE_ERROR_LIMIT_REACHED:
                    ZimbraLog.extensions.debug("Application limit reached: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_POLICIES_VIOLATION:
                    ZimbraLog.extensions
                            .debug("Temporarily blocked for policies violations: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                case RESPONSE_ERROR_TOO_MANY_REQUESTS:
                    ZimbraLog.extensions.debug("Too many requests: " + errorMsg);
                    throw ServiceException.TEMPORARILY_UNAVAILABLE();
                default:
                    ZimbraLog.extensions.warn("Unexpected error while trying to authenticate "
                            + "the user." + response.toString());
                    throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token")) {
            throw ServiceException.PARSE_ERROR("Unexpected response from social service.", null);
        }
    }

    /**
     * Check code and return range which is listed in the FacebookConstants
     * class.<br>
     * See Facebook error code range for Permission denied errors<br>
     * https://developers.facebook.com/docs/graph-api/using-graph-api/error-handling
     *
     * @param errorCode An error code from value
     * @return The Range that matches the error type
     */
    protected String inErrorCodeRange(String errorCode) {
        if (!errorCode.isEmpty()) {
            final Integer errorCodeInt = Integer.valueOf(errorCode);
            if (errorCodeInt >= 200 && errorCodeInt <= 299) {
                errorCode = "200-299";
            }
        }
        return errorCode;
    }

    /**
     * Retrieves the primary email of the user with the access_token and auth
     * token.
     *
     * @param credentials The json containing an access_token
     * @return The unique user ID
     * @throws ServiceException If there are issues determining the primary
     *                         address
     */
    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account acct) throws ServiceException {
        JsonNode json = null;
        final String authToken = credentials.get("access_token").asText();
        final String url = String.format(FacebookOAuth2Constants.USER_DETAILS_URI_TEMPLATE.getValue(),
            authToken);

        try {
            final GetMethod request = new GetMethod(url);
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.warnQuietly("There was an issue acquiring the account details.",
                    e);
            throw ServiceException.FAILURE("There was an issue acquiring the account details.",
                    null);
        }
        if (json.has("first_name") && json.has("last_name")
                && !json.get("first_name").asText().isEmpty()
                && !json.get("last_name").asText().isEmpty()) {
            return json.get("first_name").asText() + "." + json.get("last_name").asText();
        } else if (json.has("id") && !json.get("id").asText().isEmpty()) {
            return json.get("id").asText();
        }

        // if we couldn't retrieve the user first & last name, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions
            .error("The user id could not be retrieved from the social service api.");
        throw ServiceException.UNSUPPORTED();
    }
}
