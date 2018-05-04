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
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.UserForbiddenException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthDataSource;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

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
     * Yahoo client id.
     */
    protected final String clientId;

    /**
     * Yahoo client secret.
     */
    protected final String clientSecret;

    /**
     * Yahoo redirect uri.
     */
    protected final String clientRedirectUri;

    /**
     * DataSource handler for Yahoo.
     */
    protected final OAuthDataSource dataSource;

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
        protected static final String AUTHORIZE_URI_TEMPLATE = "https://api.login.yahoo.com/oauth2/request_auth?client_id=%s&redirect_uri=%s&response_type=%s";

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

        // LC Yahoo
        public static final String LC_OAUTH_CLIENT_ID = "zm_oauth_yahoo_client_id";
        public static final String LC_OAUTH_CLIENT_SECRET = "zm_oauth_yahoo_client_secret";
        public static final String LC_OAUTH_CLIENT_REDIRECT_URI = "zm_oauth_yahoo_client_redirect_uri";
        public static final String LC_OAUTH_IMPORT_CLASS = "zm_oauth_yahoo_import_class";
    }

    /**
     * Constructs a YahooOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public YahooOAuth2Handler(Configuration config) {
        super(config);
        clientId = config.getString(YahooConstants.LC_OAUTH_CLIENT_ID);
        clientSecret = config.getString(YahooConstants.LC_OAUTH_CLIENT_SECRET);
        clientRedirectUri = config.getString(YahooConstants.LC_OAUTH_CLIENT_REDIRECT_URI);
        dataSource = OAuthDataSource.createDataSource(ZDataSource.SOURCE_HOST_YAHOO);
    }

    @Override
    public String authorize(String relayState) throws GenericOAuthException {
        final String responseType = "code";
        String encodedRedirectUri = "";
        try {
            encodedRedirectUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);
        } catch (final UnsupportedEncodingException e) {
            ZimbraLog.extensions.error("Invalid redirect URI found in client config.", e);
            throw new ConfigurationException("Invalid redirect URI found in client config.");
        }

        String relayParam = "%s";
        String relayValue = "";
        String relay = StringUtils.defaultString(relayState, "");

        if (!relay.isEmpty()) {
            try {
                relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING);
            } catch (final UnsupportedEncodingException e) {
                throw new InvalidOperationException("Unable to decode relay parameter.");
            }

            try {
                relayParam = "&" + YahooConstants.RELAY_KEY + "=%s";
                relayValue = URLEncoder.encode(relay, OAuth2Constants.ENCODING);
            } catch (final UnsupportedEncodingException e) {
                throw new InvalidOperationException("Unable to encode relay parameter.");
            }
        }
        return String.format(YahooConstants.AUTHORIZE_URI_TEMPLATE + relayParam, clientId,
            encodedRedirectUri, responseType, relayValue);
    }

    @Override
    public Boolean authenticate(OAuthInfo oauthInfo) throws GenericOAuthException {
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        final HttpClientContext context = HttpClientContext.create();
        final JsonNode credentials = authenticateRequest(oauthInfo, clientRedirectUri, context);

        final String accessToken = credentials.get("access_token").asText();
        final String username = getPrimaryEmail(credentials.get("xoauth_yahoo_guid").asText(),
            accessToken, context);
        ;

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // store username, zimbraAccountId, refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
        dataSource.updateCredentials(mailbox, oauthInfo, storageFolderId);
        return true;
    }

    @Override
    public Boolean refresh(OAuthInfo oauthInfo) throws GenericOAuthException {
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        final HttpClientContext context = HttpClientContext.create();

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // get refreshToken from DataSource with end service username
        // (user@yahoo.com)
        final String refreshToken = dataSource.getRefreshToken(mailbox, oauthInfo.getUsername());

        // invalid operation if no refresh token stored for the user
        if (StringUtils.isEmpty(refreshToken)) {
            throw new InvalidOperationException("The specified user has no stored refresh token.");
        }

        // add refreshToken to oauthInfo, call authenticateRequest
        oauthInfo.setRefreshToken(refreshToken);
        final JsonNode credentials = authenticateRequest(oauthInfo, clientRedirectUri, context);

        // update credentials
        oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
        dataSource.updateCredentials(mailbox, oauthInfo, storageFolderId);
        return true;
    }

    /**
     * Builds the HTTP request for authentication.
     *
     * @param authInfo Contains the auth info to use in the request
     * @param redirectUri The user's redirect uri
     * @param context The HTTP context
     * @return Json response from the endpoint
     * @throws GenericOAuthException If there are issues performing the request
     *             or parsing for json
     */
    protected JsonNode authenticateRequest(OAuthInfo authInfo, String redirectUri,
        HttpClientContext context) throws GenericOAuthException {
        final String clientId = authInfo.getClientId();
        final String clientSecret = authInfo.getClientSecret();
        final String basicToken = Base64.getEncoder()
            .encodeToString(new String(clientId + ":" + clientSecret).getBytes());
        final String code = authInfo.getParam("code");
        final String refreshToken = authInfo.getRefreshToken();
        final HttpPost request = new HttpPost(YahooConstants.AUTHENTICATE_URI);
        final List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            params.add(new BasicNameValuePair("grant_type", "refresh_token"));
            params.add(new BasicNameValuePair("refresh_token", refreshToken));
        } else {
            // otherwise use the code
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", code));
        }
        params.add(new BasicNameValuePair("redirect_uri", redirectUri));
        params.add(new BasicNameValuePair("client_secret", clientSecret));
        params.add(new BasicNameValuePair("client_id", clientId));
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        request.setHeader("Authorization", "Basic " + basicToken);
        JsonNode json = null;
        try {
            request.setEntity(new UrlEncodedFormEntity(params));
            json = executeRequestForJson(request, context);
        } catch (final IOException e) {
            ZimbraLog.extensions.error("There was an issue acquiring the authorization token.", e);
            throw new UserUnauthorizedException(
                "There was an issue acquiring an authorization token for this user.");
        }

        // ensure the response contains the necessary credentials
        validateAuthenticateResponse(json);

        return json;
    }

    /**
     * Validates that the response from authenticate has no errors, and contains
     * the requested access information.
     *
     * @param response The json response from authenticate
     * @throws InvalidOperationException If the refresh token was deemed
     *             invalid, or incorrect redirect uri
     * @throws UserUnauthorizedException If the refresh token or code is
     *             expired, or for general rejection
     * @throws UserForbiddenException If the user did not provide authorization
     *             for the same client Id used in the authenticate
     * @throws InvalidResponseException If the response from Yahoo has no
     *             errors, but the access info is missing
     * @throws ConfigurationException If the client id or client secret are
     *             incorrect
     * @throws GenericOAuthException If there are issues with the response
     */
    protected void validateAuthenticateResponse(JsonNode response) throws GenericOAuthException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            final JsonNode errorMsg = response.get("error_description");
            switch (error) {
            case YahooConstants.RESPONSE_ERROR_ACCOUNT_NOT_AUTHORIZED:
                ZimbraLog.extensions
                    .info("User did not provide authorization for this service: " + errorMsg);
                throw new UserForbiddenException(
                    "User did not provide authorization for this service.");
            case YahooConstants.RESPONSE_ERROR_INVALID_REDIRECT_URI:
                ZimbraLog.extensions.info(
                    "Redirect does not match the one found in authorization request: " + errorMsg);
                throw new InvalidOperationException(
                    "Redirect does not match the one found in authorization request.");
            case YahooConstants.RESPONSE_ERROR_INVALID_CALLBACK:
                ZimbraLog.extensions
                    .warn("Redirect does not match the configured one expected by the server: "
                        + errorMsg);
                throw new InvalidOperationException(
                    "Redirect does not match the configured one expected by the server.");
            case YahooConstants.RESPONSE_ERROR_INVALID_REFRESH_TOKEN:
                ZimbraLog.extensions.debug("Invalid refresh token used: " + errorMsg);
                throw new InvalidOperationException("Refresh token is invalid.");
            case YahooConstants.RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE:
            case YahooConstants.RESPONSE_ERROR_INVALID_GRANT:
                ZimbraLog.extensions.debug("Invalid authorization token used: " + errorMsg);
                throw new UserUnauthorizedException(
                    "Authorization token is expired or invalid. Unable to authenticate the user.");
            case YahooConstants.RESPONSE_ERROR_TOKEN_EXPIRED:
                ZimbraLog.extensions.debug("Refresh token is expired: " + errorMsg);
                throw new UserUnauthorizedException(
                    "Refresh token is expired. Unable to authenticate the user.");
            case YahooConstants.RESPONSE_ERROR_INVALID_CLIENT:
            case YahooConstants.RESPONSE_ERROR_INVALID_CLIENT_SECRET:
                ZimbraLog.extensions
                    .warn("Invalid client or client secret provided to mail server: " + errorMsg);
                throw new ConfigurationException("Invalid client details provided to mail server.");
            default:
                ZimbraLog.extensions
                    .warn("Unexpected error while trying to authenticate the user: " + errorMsg);
                throw new UserUnauthorizedException("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("refresh_token")
            || !response.has("xoauth_yahoo_guid")) {
            throw new InvalidResponseException("Unexpected response from mail server.");
        }

    }

    /**
     * Retrieves the primary email of the user with the specified guid and auth
     * token.
     *
     * @param guid The identifier for the user
     * @param authToken The auth for the user
     * @param context The http context
     * @return The user's primary email
     * @throws GenericOAuthExcpetion If there are issues
     */
    protected String getPrimaryEmail(String guid, String authToken, HttpClientContext context)
        throws GenericOAuthException {
        final String url = String.format(YahooConstants.PROFILE_URI, guid);
        final HttpGet request = new HttpGet(url);
        request.setHeader("Content-Type", "application/x-www-form-urlencoded");
        request.setHeader("Accept", "application/json");
        request.setHeader("Authorization", "Bearer " + authToken);

        JsonNode json = null;
        try {
            json = executeRequestForJson(request, context);
        } catch (final IOException e) {
            ZimbraLog.extensions.error("There was an issue acquiring the user's profile.", e);
            throw new GenericOAuthException("There was an issue acquiring the user's profile.");
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
        throw new InvalidResponseException(
            "The primary email could not be retrieved from the profile api.");
    }

}
