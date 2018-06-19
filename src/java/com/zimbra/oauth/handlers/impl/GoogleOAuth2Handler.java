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
import com.zimbra.client.ZFolder.View;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;

/**
 * The GoogleOAuth2Handler class.<br>
 * Google OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class GoogleOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    /**
     * Contains constants used in this implementation.
     */
    protected class GoogleConstants {

        /**
         * Invalid redirect response code from Google.
         */
        protected static final String RESPONSE_ERROR_INVALID_REDIRECT_URI = "REDIRECT_URI_MISMATCH";

        /**
         * Invalid authorization code response code from Google.
         */
        protected static final String RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE = "INVALID_AUTHORIZATION_CODE";

        /**
         * Invalid grant response code from Google.
         */
        protected static final String RESPONSE_ERROR_INVALID_GRANT = "INVALID_GRANT";

        /**
         * Unsupported grant type response code from Google.
         */
        protected static final String RESPONSE_ERROR_UNSUPPORTED_GRANT_TYPE = "UNSUPPORTED_GRANT_TYPE";

        /**
         * Invalid client response code from Google.
         */
        protected static final String RESPONSE_ERROR_INVALID_CLIENT = "INVALID_CLIENT";

        /**
         * Invalid request code from Google.
         */
        protected static final String RESPONSE_ERROR_INVALID_REQUEST = "INVALID_REQUEST";

        /**
         * The authorize endpoint for Google.
         */
        protected static final String AUTHORIZE_URI_TEMPLATE = "https://accounts.google.com/o/oauth2/v2/auth?prompt=consent&access_type=offline&client_id=%s&redirect_uri=%s&response_type=%s&scope=%s";

        /**
         * The profile endpoint for Google.
         */
        protected static final String PROFILE_URI = "https://www.googleapis.com/plus/v1/people/me";

        /**
         * The authenticate endpoint for Google.
         */
        protected static final String AUTHENTICATE_URI = "https://www.googleapis.com/oauth2/v4/token";

        /**
         * The contacts endpoint for Google.
         */
        protected static final String CONTACTS_URI = "https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses,organizations,phoneNumbers,addresses,events,birthdays,biographies,nicknames,urls,photos,userDefined,skills,interests,braggingRights,relationshipInterests,relationshipStatuses,occupations,taglines";

        /**
         * The contacts pagination size for Google.
         */
        protected static final String CONTACTS_PAGE_SIZE = "100";

        /**
         * The scope required for Google.
         */
        protected static final String REQUIRED_SCOPES = "email";

        /**
         * The relay key for Google.
         */
        protected static final String RELAY_KEY = "state";

        /**
         * The implementation name.
         */
        public static final String CLIENT_NAME = "google";

        /**
         * The implementation host.
         */
        public static final String HOST_GOOGLE = "googleapis.com";
    }

    /**
     * Constructs a GoogleOAuth2Handler object.
     *
     * @param config For accessing configured properties
     * @throws ServiceException
     */
    public GoogleOAuth2Handler(Configuration config) throws ServiceException {
        super(config, GoogleConstants.CLIENT_NAME, GoogleConstants.HOST_GOOGLE);
        authenticateUri = GoogleConstants.AUTHENTICATE_URI;
        relayKey = GoogleConstants.RELAY_KEY;
        dataSource.addImportClass(View.contact.name(),
            GoogleContactsImport.class.getCanonicalName());

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
     *             PARSE_ERROR If the response from Google has no errors, but
     *             the access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            final JsonNode errorMsg = response.get("error_description");
            ZimbraLog.extensions.debug("Response from google: %s", response.asText());
            switch (error.toUpperCase()) {
            case GoogleConstants.RESPONSE_ERROR_INVALID_REDIRECT_URI:
                ZimbraLog.extensions.info(
                    "Redirect does not match the one found in authorization request: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Redirect does not match the one found in authorization request.");
            case GoogleConstants.RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE:
            case GoogleConstants.RESPONSE_ERROR_INVALID_GRANT:
                ZimbraLog.extensions
                    .debug("Invalid authorization / refresh token used: " + errorMsg);
                throw ServiceException.PERM_DENIED(
                    "Authorization or refresh token is expired or invalid. Unable to authenticate the user.");
            case GoogleConstants.RESPONSE_ERROR_UNSUPPORTED_GRANT_TYPE:
                ZimbraLog.extensions.debug("Unsupported grant type used: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Unsupported grant type used. Unable to authenticate the user.");
            case GoogleConstants.RESPONSE_ERROR_INVALID_CLIENT:
                ZimbraLog.extensions.warn(
                    "Invalid client or client secret provided to the social service: " + errorMsg);
                throw ServiceException
                    .OPERATION_DENIED("Invalid client details provided to the social service.");
            case GoogleConstants.RESPONSE_ERROR_INVALID_REQUEST:
                ZimbraLog.extensions.warn("Invalid request parameter was provided: " + errorMsg);
                throw ServiceException
                    .OPERATION_DENIED("An invalid request parameter was provided.");
            default:
                ZimbraLog.extensions
                    .warn("Unexpected error while trying to authenticate the user: " + errorMsg);
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("refresh_token")) {
            throw ServiceException.PARSE_ERROR("Unexpected response from social service.", null);
        }

    }

}
