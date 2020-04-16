/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
 * Copyright (C) 2020 Synacor, Inc.
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
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2CacheHandler;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * The WebexOAuth2Handler class.<br>
 * Webex OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2020
 */
public class WebexOAuth2Handler extends OAuth2Handler implements IOAuth2Handler, IOAuth2CacheHandler {

    private final String ERROR_TEMPLATE = "%s | Webex error tracking id: %s | Reason: %s";

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum WebexOAuth2Constants {

        /**
         * The authorize endpoint for Webex.
         */
        AUTHORIZE_URI_TEMPLATE("https://api.ciscospark.com/v1/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The profile endpoint for Webex.
         */
        PROFILE_URI("https://api.ciscospark.com/v1/people/me"),

        /**
         * The authenticate endpoint for Webex.
         */
        AUTHENTICATE_URI("https://api.ciscospark.com/v1/access_token"),

        /**
         * The scope required for Webex.
         */
        REQUIRED_SCOPES("spark:people_read"),

        /**
         * The scope delimiter for Webex.
         */
        SCOPE_DELIMITER(" "),

        /**
         * The relay key for Webex.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("webex"),

        /**
         * The implementation host.
         */
        HOST_WEBEX("api.ciscospark.com");

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
        private WebexOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a WebexOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public WebexOAuth2Handler(Configuration config) {
        super(config, WebexOAuth2Constants.CLIENT_NAME.getValue(), WebexOAuth2Constants.HOST_WEBEX.getValue());
        authenticateUri = WebexOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = WebexOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = WebexOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = WebexOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = WebexOAuth2Constants.RELAY_KEY.getValue();
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
     *             PARSE_ERROR If the response from Webex has no errors, but
     *             the access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("errors")) {
            final String errorMsg = response.get("message").asText();
            final String trackingId = response.get("trackingId").asText();
            ZimbraLog.extensions.debug("Response from webex: %s", response.asText());
            ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                "There was an issue during oauth token request.", trackingId, errorMsg));
            throw ServiceException.PERM_DENIED("There was an issue during oauth token request.");
        }

        // ensure the tokens we requested are present
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
        final HttpGet request = new HttpGet(WebexOAuth2Constants.PROFILE_URI.getValue());
        request.setHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer " + authToken);

        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.errorQuietly("There was an issue acquiring the client's user info.", e);
            throw ServiceException.FAILURE("There was an issue acquiring the client's user info.", null);
        }

        if (json != null && json.hasNonNull("id")) {
            return json.get("id").asText();
        }

        // if we couldn't retrieve the handle identifier, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions.error(
            "The primary id could not be retrieved from the profile api. Check social app's configured scopes.");
        throw ServiceException.UNSUPPORTED();
    }

    @Override
    protected String buildScopeString(Account account, String type) {
        final String scopes = super.buildScopeString(account, type);
        if (StringUtils.isNotEmpty(scopes)) {
            // webex scopes need % encoded spaces and colons
            try {
                return URLEncoder.encode(scopes, OAuth2Constants.ENCODING.getValue())
                    .replaceAll("\\+", "%20");
            } catch (final UnsupportedEncodingException e) {
                ZimbraLog.extensions.error("There was an issue encoding the scopes: %s", scopes);
            }
        }
        return scopes;
    }

}
