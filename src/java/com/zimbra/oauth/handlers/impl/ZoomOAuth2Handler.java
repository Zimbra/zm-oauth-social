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
import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.methods.HttpGet;
import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * The ZoomOAuth2Handler class.<br>
 * Zoom OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class ZoomOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    private final String ERROR_TEMPLATE = "%s | Zoom error code: %s | Reason: %s";

    /**
     * Contains error constants used in this implementation.
     */
    protected enum ZoomErrorConstants {

        /**
         * Invalid request response code from Zoom.
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
        private ZoomErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static ZoomErrorConstants fromString(String code) {
            for (final ZoomErrorConstants t : ZoomErrorConstants.values()) {
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
    protected enum ZoomOAuth2Constants {

        /**
         * The authorize endpoint for Zoom.
         */
        AUTHORIZE_URI_TEMPLATE("https://zoom.us/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The profile endpoint for Zoom.
         */
        PROFILE_URI("https://zoom.us/v2/users/me"),

        /**
         * The authenticate endpoint for Zoom.
         */
        AUTHENTICATE_URI("https://zoom.us/oauth/token"),

        /**
         * The scope required for Zoom.
         */
        REQUIRED_SCOPES("user:read+meeting:write+webinar:write"),

        /**
         * The scope delimiter for Zoom.
         */
        SCOPE_DELIMITER("+"),

        /**
         * The relay key for Zoom.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("zoom"),

        /**
         * The implementation host.
         */
        HOST_ZOOM("zoom.us");

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
        private ZoomOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a ZoomOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public ZoomOAuth2Handler(Configuration config) {
        super(config, ZoomOAuth2Constants.CLIENT_NAME.getValue(), ZoomOAuth2Constants.HOST_ZOOM.getValue());
        authenticateUri = ZoomOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = ZoomOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = ZoomOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = ZoomOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = ZoomOAuth2Constants.RELAY_KEY.getValue();
    }

    @Override
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("access_token", tokenResponse.get("access_token").asText());
        params.put("user_id", oauthInfo.getUsername());
        oauthInfo.setParams(params);
    }

    /**
     * Validates that the token response has no errors, and contains the
     * requested access information.
     *
     * @param response The json token response
     * @throws ServiceException<br>
     *             OPERATION_DENIED If the refresh token request was deemed invalid due
     *             to inorrect request parameters (code, client id/secret, etc).<br>
     *             PARSE_ERROR If the response from Zoom has no errors, but
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
            if (response.has("reason")) {
                errorMsg = response.get("reason").asText();
            }
            ZimbraLog.extensions.debug("Response from zoom: %s", response.asText());
            switch (ZoomErrorConstants.fromString(StringUtils.lowerCase(error))) {
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
        // TODO: update this to require refresh_token when zoom adds support for auto-expiring tokens
        // see https://api.zoom.com/docs/rotating-and-refreshing-credentials
        if (!response.has("access_token") || !response.has("refresh_token")) {
            throw ServiceException.PARSE_ERROR(
                "Unexpected response from social service. Missing any of required params: access_token, refresh_token.",
                null);
        }

    }

    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        final String authToken = credentials.get("access_token").asText();
        final HttpGet request = new HttpGet(ZoomOAuth2Constants.PROFILE_URI.getValue());
        request.setHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer " + authToken);

        JsonNode json = null;
        try {
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

}
