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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;

/**
 * The SlackOAuth2Handler class.<br>
 * Slack OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class SlackOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    private final String ERROR_TEMPLATE = "%s | Slack error code: %s";

    /**
     * Contains error constants used in this implementation.
     * @see https://api.slack.com/methods/oauth.access
     */
    protected enum SlackErrorConstants {

        /**
         * Invalid redirect response code from Slack.
         */
        RESPONSE_ERROR_INVALID_REDIRECT_URI("bad_redirect_uri"),

        /**
         * Invalid authorization code response code from Slack.
         */
        RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE("invalid_code"),

        /**
         * Invalid arguments response codes from Slack.
         */
        RESPONSE_ERROR_INVALID_ARGUMENTS("invalid_arguments"),
        RESPONSE_ERROR_INVALID_ARGUMENT_NAME("invalid_arg_name"),

        /**
         * Invalid client secret response code from Slack.
         */
        RESPONSE_ERROR_INVALID_CLIENT_SECRET("bad_client_secret"),

        /**
         * Invalid client response code from Slack.
         */
        RESPONSE_ERROR_INVALID_CLIENT("invalid_client_id"),

        /**
         * The workspace associated with your request is currently
         * undergoing migration to an Enterprise Organization.
         * Web API and other platform operations will be intermittently
         * unavailable until the transition is complete.<br>
         * This can be handled as generic error case.
         */
        RESPONSE_ERROR_MIGRATION("team_added_to_org"),

        /**
         * The method was called via a POST request,
         * but the POST data was either missing or truncated.<br>
         * This key is designated per Slack official documentation.
         */
        RESPONSE_ERROR_MISSING_DATA("request_timeout"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("fatal_error");

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
        private SlackErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static SlackErrorConstants fromString(String code) {
            for (final SlackErrorConstants t : SlackErrorConstants.values()) {
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
    protected enum SlackOAuth2Constants {

        /**
         * The authorize endpoint for Slack.
         */
        AUTHORIZE_URI_TEMPLATE("https://slack.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The authenticate endpoint for Slack.
         */
        AUTHENTICATE_URI("https://slack.com/api/oauth.access"),

        /**
         * The scopes required for Slack.
         */
        REQUIRED_SCOPES(""),

        /**
         * The scope delimiter for Slack.
         */
        SCOPE_DELIMITER(","),

        /**
         * Format for identifier as: `team id-user id`.
         */
        IDENTIFIER_TEMPLATE("%s-%s"),

        /**
         * The relay key for Slack.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("slack"),

        /**
         * The implementation host.
         */
        HOST_SLACK("api.slack.com");

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
        private SlackOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a SlackOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public SlackOAuth2Handler(Configuration config) {
        super(config, SlackOAuth2Constants.CLIENT_NAME.getValue(), SlackOAuth2Constants.HOST_SLACK.getValue());
        authenticateUri = SlackOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = SlackOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = SlackOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = SlackOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = SlackOAuth2Constants.RELAY_KEY.getValue();
    }

    @Override
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("access_token", tokenResponse.get("access_token").asText());
        params.put("user_id", tokenResponse.get("user_id").asText());
        params.put("team_id", tokenResponse.get("team_id").asText());
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
     *             OPERATION_DENIED If the refresh token was deemed invalid, or
     *             incorrect redirect uri.<br>
     *             If the client id or client secret are incorrect.<br>
     *             PARSE_ERROR If the response from Slack has no errors, but
     *             the access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            ZimbraLog.extensions.debug("Response from slack: %s", response.asText());
            switch (SlackErrorConstants.fromString(StringUtils.lowerCase(error))) {
            case RESPONSE_ERROR_INVALID_REDIRECT_URI:
                ZimbraLog.extensions.info(String.format(ERROR_TEMPLATE,
                    "Redirect does not match the one found in authorization request.", error));
                throw ServiceException.OPERATION_DENIED(
                    "Redirect does not match the one found in authorization request.");
            case RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE:
                ZimbraLog.extensions.debug(String.format(ERROR_TEMPLATE,
                        "Invalid authorization / refresh token used.", error));
                throw ServiceException.PERM_DENIED(
                    "Authorization or refresh token is expired or invalid. Unable to authenticate the user.");
            case RESPONSE_ERROR_INVALID_CLIENT:
            case RESPONSE_ERROR_INVALID_CLIENT_SECRET:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Invalid client or client secret provided to the social service.", error));
                throw ServiceException
                    .OPERATION_DENIED("Invalid client details provided to the social service.");
            case RESPONSE_ERROR_INVALID_ARGUMENTS:
            case RESPONSE_ERROR_INVALID_ARGUMENT_NAME:
            case RESPONSE_ERROR_MISSING_DATA:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Invalid request parameter was provided.", error));
                throw ServiceException
                    .OPERATION_DENIED("An invalid request parameter was provided.");
            default:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Unexpected error while trying to authenticate the user.", error));
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        // TODO: update this to require refresh_token when slack adds support for auto-expiring tokens
        // see https://api.slack.com/docs/rotating-and-refreshing-credentials
        if (!response.has("access_token") || !response.has("user_id") || !response.has("team_id")) {
            throw ServiceException.PARSE_ERROR(
                "Unexpected response from social service. Missing any of required params: access_token, user_id, team_id.",
                null);
        }

    }

    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        final String teamId = credentials.get("team_id").asText();
        final String userId = credentials.get("user_id").asText();
        if (StringUtils.isEmpty(teamId) || StringUtils.isEmpty(userId)) {
            throw ServiceException.PARSE_ERROR("Authentication response has empty user identifier parameters.",
                null);
        }
        return String.format(SlackOAuth2Constants.IDENTIFIER_TEMPLATE.getValue(), teamId, userId);
    }

}
