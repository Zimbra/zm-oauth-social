/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
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

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZDataSource;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;

/**
 * The YahooOAuth2Handler class.<br>
 * Yahoo OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class YahooOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    /**
     * Contains constants used in this implementation.
     */
    protected class YahooConstants {

        /**
         * Unauthorized response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_ACCOUNT_NOT_AUTHORIZED = "ACCOUNT_NOT_AUTHORIZED";

        /**
         * Invalid client response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_CLIENT = "INVALID_CLIENT";

        /**
         * Invalid client secret response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_CLIENT_SECRET = "INVALID_CLIENT_SECRET";

        /**
         * Invalid redirect response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_REDIRECT_URI = "INVALID_REDIRECT_URI";

        /**
         * Invalid callback response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_CALLBACK = "INVALID_CALLBACK";

        /**
         * Invalid refresh token response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_REFRESH_TOKEN = "INVALID_REFRESH_TOKEN";

        /**
         * Invalid authorization code response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE = "INVALID_AUTHORIZATION_CODE";

        /**
         * Invalid grant response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_INVALID_GRANT = "INVALID_GRANT";

        /**
         * Token expired response code from Yahoo.
         */
        protected static final String RESPONSE_ERROR_TOKEN_EXPIRED = "TOKEN_EXPIRED";

        /**
         * The authorize endpoint for Yahoo.
         */
        protected static final String AUTHORIZE_URI_TEMPLATE = "https://api.login.yahoo.com/oauth2/request_auth?client_id=%s&redirect_uri=%s&response_type=%s%s";

        /**
         * The profile endpoint for Yahoo.
         */
        protected static final String PROFILE_URI = "https://social.yahooapis.com/v1/user/%s/profile";

        /**
         * The authenticate endpoint for Yahoo.
         */
        protected static final String AUTHENTICATE_URI = "https://api.login.yahoo.com/oauth2/get_token";

        /**
         * The relay key for Yahoo.
         */
        protected static final String RELAY_KEY = "state";

        /**
         * The implementation name.
         */
        public static final String CLIENT_NAME = "yahoo";
    }

    /**
     * Constructs a YahooOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public YahooOAuth2Handler(Configuration config) {
        super(config, YahooConstants.CLIENT_NAME, ZDataSource.SOURCE_HOST_YAHOO);
        authenticateUri = YahooConstants.AUTHENTICATE_URI;
        authorizeUriTemplate = YahooConstants.AUTHORIZE_URI_TEMPLATE;
        relayKey = YahooConstants.RELAY_KEY;
    }

    /**
     * Validates that the response from authenticate has no errors, and contains
     * the requested access information.
     *
     * @param response The json response from authenticate
     * @throws ServiceException<br>
     *             FORBIDDEN If the user has no authorization credentials.<br>
     *             OPERATION_DENIED If the refresh token was deemed invalid, or
     *             incorrect redirect uri.<br>
     *             If the client id or client secret are incorrect.<br>
     *             PARSE_ERROR If the response from Yahoo has no errors, but the
     *             access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateAuthenticateResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            final JsonNode errorMsg = response.get("error_description");
            switch (error) {
            case YahooConstants.RESPONSE_ERROR_ACCOUNT_NOT_AUTHORIZED:
                ZimbraLog.extensions
                    .info("User did not provide authorization for this service: " + errorMsg);
                throw ServiceException
                    .FORBIDDEN("User did not provide authorization for this service.");
            case YahooConstants.RESPONSE_ERROR_INVALID_REDIRECT_URI:
                ZimbraLog.extensions.info(
                    "Redirect does not match the one found in authorization request: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Redirect does not match the one found in authorization request.");
            case YahooConstants.RESPONSE_ERROR_INVALID_CALLBACK:
                ZimbraLog.extensions
                    .warn("Redirect does not match the configured one expected by the server: "
                        + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Redirect does not match the configured one expected by the server.");
            case YahooConstants.RESPONSE_ERROR_INVALID_REFRESH_TOKEN:
                ZimbraLog.extensions.debug("Invalid refresh token used: " + errorMsg);
                throw ServiceException.PERM_DENIED("Refresh token is invalid.");
            case YahooConstants.RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE:
            case YahooConstants.RESPONSE_ERROR_INVALID_GRANT:
                ZimbraLog.extensions.debug("Invalid authorization token used: " + errorMsg);
                throw ServiceException.PERM_DENIED(
                    "Authorization token is expired or invalid. Unable to authenticate the user.");
            case YahooConstants.RESPONSE_ERROR_TOKEN_EXPIRED:
                ZimbraLog.extensions.debug("Refresh token is expired: " + errorMsg);
                throw ServiceException
                    .PERM_DENIED("Refresh token is expired. Unable to authenticate the user.");
            case YahooConstants.RESPONSE_ERROR_INVALID_CLIENT:
            case YahooConstants.RESPONSE_ERROR_INVALID_CLIENT_SECRET:
                ZimbraLog.extensions
                    .warn("Invalid client or client secret provided to mail server: " + errorMsg);
                throw ServiceException
                    .OPERATION_DENIED("Invalid client details provided to Yahoo.");
            default:
                ZimbraLog.extensions
                    .warn("Unexpected error while trying to authenticate the user: " + errorMsg);
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("refresh_token")
            || !response.has("xoauth_yahoo_guid")) {
            throw ServiceException.PARSE_ERROR("Unexpected response from social service.", null);
        }

    }

    /**
     * Retrieves the primary email of the user with the specified guid and auth
     * token.
     *
     * @param guid The identifier for the user
     * @param authToken The auth for the user
     * @return The user's primary email
     * @throws ServiceExcpetion If there are issues
     */
    @Override
    protected String getPrimaryEmail(JsonNode credentials) throws ServiceException {
        final String guid = credentials.get("xoauth_yahoo_guid").asText();
        final String authToken = credentials.get("access_token").asText();
        final String url = String.format(YahooConstants.PROFILE_URI, guid);
        final GetMethod request = new GetMethod(url);
        request.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        request.setRequestHeader("Accept", "application/json");
        request.setRequestHeader("Authorization", "Bearer " + authToken);

        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.errorQuietly("There was an issue acquiring the user's profile.",
                e);
            throw ServiceException.PROXY_ERROR("There was an issue acquiring the user's profile.",
                null);
        }

        final JsonNode profile = json.get("profile");
        if (profile != null) {
            final JsonNode profileEmails = profile.get("emails");
            if (profileEmails != null && profileEmails.has(0)) {
                final JsonNode profileHandle = profileEmails.get(0);
                if (profileHandle.has("handle")) {
                    return profileHandle.get("handle").asText();
                }
            }
        }
        // if we couldn't retrieve the handle email, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions
            .error("The primary email could not be retrieved from the profile api.");
        throw ServiceException.UNSUPPORTED();
    }

}
