/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
 * Copyright (C) 2019 Synacor, Inc.
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;

/**
 * The DropboxOAuth2Handler class.<br>
 * Dropbox OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class DropboxOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    private final String ERROR_TEMPLATE = "%s | Dropbox error code: %s | Reason: %s";

    /**
     * Contains error constants used in this implementation.
     */
    protected enum DropboxErrorConstants {

        /**
         * Invalid request response code from Dropbox.
         */
        RESPONSE_ERROR_INVALID_REQUEST("invalid_request"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("internal_error");

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
        private DropboxErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static DropboxErrorConstants fromString(String code) {
            for (final DropboxErrorConstants t : DropboxErrorConstants.values()) {
                if (StringUtils.equals(t.getValue(), code)) {
                    return t;
                }
            }
            return DEFAULT_ERROR;
        }

    }

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum DropboxOAuth2Constants {

        /**
         * The authorize endpoint for Dropbox.
         */
        AUTHORIZE_URI_TEMPLATE("https://www.dropbox.com/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=%s"),

        /**
         * The profile endpoint for Dropbox.
         */
        PROFILE_URI("https://api.dropboxapi.com/2/users/get_account"),

        /**
         * The authenticate endpoint for Dropbox.
         */
        AUTHENTICATE_URI("https://api.dropboxapi.com/oauth2/token"),

        /**
         * The scope required for Dropbox.
         */
        REQUIRED_SCOPES(""),

        /**
         * The scope delimiter for Dropbox.
         */
        SCOPE_DELIMITER("+"),

        /**
         * The relay key for Dropbox.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("dropbox"),

        /**
         * The implementation host.
         */
        HOST_DROPBOX("dropbox.us");

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
        private DropboxOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a DropboxOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public DropboxOAuth2Handler(Configuration config) {
        super(config, DropboxOAuth2Constants.CLIENT_NAME.getValue(),
            DropboxOAuth2Constants.HOST_DROPBOX.getValue());
        authenticateUri = DropboxOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = DropboxOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        relayKey = DropboxOAuth2Constants.RELAY_KEY.getValue();
    }

    /**
     * Dropbox won't allow both authorization header and client id/secret parameters.
     * @see OAuth2Handler#getTokenRequest
     */
    @Override
    protected JsonNode getToken(OAuthInfo authInfo, String basicToken) throws ServiceException {
        final String refreshToken = authInfo.getRefreshToken();
        final HttpPost request = new HttpPost(authInfo.getTokenUrl());
        final List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            params.add(new BasicNameValuePair("grant_type", "refresh_token"));
            params.add(new BasicNameValuePair("refresh_token", refreshToken));
        } else {
            // otherwise use the code
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", authInfo.getParam("code")));
        }
        params.add(new BasicNameValuePair("redirect_uri", authInfo.getClientRedirectUri()));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            "Basic " + basicToken);
        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
            ZimbraLog.extensions.debug("Request for auth token completed.");
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization token.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization token for this user.");
        }

        return json;
    }

    @Override
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("access_token", tokenResponse.get("access_token").asText());
        params.put("email", oauthInfo.getUsername());
        oauthInfo.setParams(params);
    }

    @Override
    protected String getStorableToken(JsonNode credentials) {
        return credentials.get("access_token").asText();
    }

    @Override
    public Boolean refresh(OAuthInfo oauthInfo) throws ServiceException {
        ZimbraLog.extensions.info("Refresh is not supported for: %s", client);
        throw ServiceException.UNSUPPORTED();
    }

    /**
     * Validates that the token response has no errors, and contains the
     * requested access information.
     *
     * @param response The json token response
     * @throws ServiceException<br>
     *             OPERATION_DENIED If the refresh token request was deemed invalid due
     *             to inorrect request parameters (code, client id/secret, etc).<br>
     *             PARSE_ERROR If the response from Dropbox has no errors, but
     *             the access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            String errorMsg = error;
            if (response.has("error_description")) {
                errorMsg = response.get("error_description").asText();
            }
            ZimbraLog.extensions.debug("Response from dropbox: %s", response.asText());
            switch (DropboxErrorConstants.fromString(StringUtils.lowerCase(error))) {
            case RESPONSE_ERROR_INVALID_REQUEST:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Invalid oauth token request parameter(s) provided, check configuration.",
                    error, errorMsg));
                throw ServiceException
                    .OPERATION_DENIED("Invalid oauth token request parameter(s) provided.");
            default:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Unexpected error while trying to authenticate the user.", error, errorMsg));
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("account_id")) {
            throw ServiceException.PARSE_ERROR(
                "Unexpected response from social service. Missing any of required params: access_token, account_id.",
                null);
        }

    }

    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        final String authToken = credentials.get("access_token").asText();
        final HttpPost request = new HttpPost(DropboxOAuth2Constants.PROFILE_URI.getValue());
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            "Bearer " + authToken);
        final Map<String, String> params = new HashMap<String, String>(1);
        params.put("account_id", credentials.get("account_id").asText());

        JsonNode json = null;
        try {
            request.setEntity(new StringEntity(OAuth2JsonUtilities.objectToJson(params),
                ContentType.create(ContentType.APPLICATION_JSON.getMimeType(), OAuth2Constants.ENCODING.getValue())));
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the user's email address.", e);
            throw ServiceException.FAILURE("There was an issue acquiring the user's email address.",
                null);
        }

        if (json != null && json.has("email")) {
            return json.get("email").asText();
        }
        // if we couldn't retrieve the handle email, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions.error(
            "The primary email could not be retrieved from the profile api. Check social app's configured scopes.");
        throw ServiceException.UNSUPPORTED();
    }

    @Override
    protected boolean isRefreshable() {
        return false;
    }

}
