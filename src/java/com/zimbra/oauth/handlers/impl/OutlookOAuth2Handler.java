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

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;

/**
 * The OutlookOAuth2Handler class.<br>
 * Outlook OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class OutlookOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    /**
     * Contains constants used in this implementation.
     */
    protected class OutlookConstants {

        /**
         * Invalid request error from Outlook.<br>
         * Protocol error, such as a missing required parameter.
         */
        protected static final String RESPONSE_ERROR_INVALID_REQUEST = "invalid_request";

        /**
         * Unauthorized client error from Outlook.<br>
         * The client application is not permitted to request an authorization
         * code.
         */
        protected static final String RESPONSE_ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";

        /**
         * Access denied error from Outlook.<br>
         * Resource owner denied consent.
         */
        protected static final String RESPONSE_ERROR_ACCESS_DENIED = "access_denied";

        /**
         * Server error, error from Outlook.<br>
         * The server encountered an unexpected error.
         */
        protected static final String RESPONSE_ERROR_SERVER_ERROR = "server_error";

        /**
         * Temporarily unavailable error from Outlook.<br>
         * The server is temporarily too busy to handle the request.
         */
        protected static final String RESPONSE_ERROR_TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

        /**
         * Invalid resource error from Outlook.<br>
         * The target resource is invalid because it does not exist, Azure AD
         * cannot find it, or it is not correctly configured.
         */
        protected static final String RESPONSE_ERROR_INVALID_RESOURCE = "invalid_resource";

        /**
         * Unsupported response type error from Outlook.<br>
         * The authorization server does not support the response type in the
         * request.
         */
        protected static final String RESPONSE_ERROR_RESPONSE_TYPE = "unsupported_response_type";

        /**
         * The authorize endpoint for Outlook.
         */
        protected static final String AUTHORIZE_URI_TEMPLATE = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s";

        /**
         * The profile endpoint for Outlook.
         */
        protected static final String PROFILE_URI = "https://www.outlookapis.com/auth/userinfo.email";

        /**
         * The authenticate endpoint for Outlook.
         */
        protected static final String AUTHENTICATE_URI = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

        /**
         * The relay key for Outlook.
         */
        protected static final String RELAY_KEY = "state";

        /**
         * The scope required for Outlook.
         */
        protected static final String REQUIRED_SCOPES = "email";

        /**
         * The implementation name.
         */
        public static final String CLIENT_NAME = "outlook";

        /**
         * The implementation host.
         */
        public static final String HOST_OUTLOOK = "microsoftonline.com";
    }

    /**
     * Constructs an OutlookOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public OutlookOAuth2Handler(Configuration config) {
        super(config, OutlookConstants.CLIENT_NAME, OutlookConstants.HOST_OUTLOOK);
        authenticateUri = OutlookConstants.AUTHENTICATE_URI;
        relayKey = OutlookConstants.RELAY_KEY;
    }

    /**
     * Validates that the token response has no errors, and contains
     * the requested access information.
     *
     * @param response The json token response
     * @throws ServiceException<br>
     *             FORBIDDEN If the social service rejects request as
     *             `access_denied`.<br>
     *             OPERATION_DENIED If the refresh token was deemed invalid, or
     *             incorrect redirect uri.<br>
     *             If the client id or client secret are incorrect.<br>
     *             PARSE_ERROR If response from Outlook has no errors, but the
     *             access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.<br>
     *             PROXY_ERROR If the social service is unable to respond
     *             normally.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            final JsonNode errorMsg = response.get("error_description");
            switch (error) {
            case OutlookConstants.RESPONSE_ERROR_INVALID_REQUEST:
                ZimbraLog.extensions.warn("Invalid token request parameters: " + errorMsg);
                throw ServiceException
                    .OPERATION_DENIED("The token request parameters are invalid.");
            case OutlookConstants.RESPONSE_ERROR_UNAUTHORIZED_CLIENT:
                ZimbraLog.extensions
                    .warn("The specified client details provided to the social service are invalid: "
                        + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "The specified client details provided to the social service are invalid.");
            case OutlookConstants.RESPONSE_ERROR_ACCESS_DENIED:
                ZimbraLog.extensions
                    .info("User did not provide authorization for this service: " + errorMsg);
                throw ServiceException
                    .FORBIDDEN("User did not provide authorization for this service.");
            case OutlookConstants.RESPONSE_ERROR_SERVER_ERROR:
            case OutlookConstants.RESPONSE_ERROR_TEMPORARILY_UNAVAILABLE:
                ZimbraLog.extensions
                    .debug("There was an issue with the remote social service: " + errorMsg);
                throw ServiceException
                    .PROXY_ERROR("There was an issue with the remote social service.", null);
            case OutlookConstants.RESPONSE_ERROR_INVALID_RESOURCE:
                ZimbraLog.extensions.debug("Invalid resource: " + errorMsg);
                throw ServiceException.PERM_DENIED("The specified resource is invalid.");
            case OutlookConstants.RESPONSE_ERROR_RESPONSE_TYPE:
                ZimbraLog.extensions.info("Requested response type is not supported: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Requested response type is not supported by the social service.");
            default:
                ZimbraLog.extensions
                    .warn("Unexpected error while trying to authenticate the user: " + errorMsg);
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("refresh_token")) {
            throw ServiceException.PARSE_ERROR("Unexpected response from mail server.", null);
        }
    }

}
