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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.soap.admin.type.DataSourceType;

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
     * Contains error constants used in this implementation.
     */
    protected enum GoogleErrorConstants {

        /**
         * Invalid redirect response code from Google.
         */
        RESPONSE_ERROR_INVALID_REDIRECT_URI("REDIRECT_URI_MISMATCH"),

        /**
         * Invalid authorization code response code from Google.
         */
        RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE("INVALID_AUTHORIZATION_CODE"),

        /**
         * Invalid grant response code from Google.
         */
        RESPONSE_ERROR_INVALID_GRANT("INVALID_GRANT"),

        /**
         * Unsupported grant type response code from Google.
         */
        RESPONSE_ERROR_UNSUPPORTED_GRANT_TYPE("UNSUPPORTED_GRANT_TYPE"),

        /**
         * Invalid client response code from Google.
         */
        RESPONSE_ERROR_INVALID_CLIENT("INVALID_CLIENT"),

        /**
         * Invalid request code from Google.
         */
        RESPONSE_ERROR_INVALID_REQUEST("INVALID_REQUEST"),

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
        private GoogleErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static GoogleErrorConstants fromString(String code) {
            for (final GoogleErrorConstants t : GoogleErrorConstants.values()) {
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
    protected enum GoogleContactConstants {

        /**
         * The contacts endpoint for Google.
         */
        CONTACTS_URI("https://people.googleapis.com/v1/people/me/connections?personFields=names,emailAddresses,organizations,phoneNumbers,addresses,events,birthdays,biographies,nicknames,urls,photos,userDefined,skills,interests,braggingRights,relationshipInterests,relationshipStatuses,occupations,taglines"),

        /**
         * The contacts pagination size for Google.
         */
        CONTACTS_PAGE_SIZE("100"),

        /**
         * The contacts image name template for Google.
         */
        CONTACTS_IMAGE_NAME_TEMPLATE("google-profile-image%s");

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
        private GoogleContactConstants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum GoogleOAuth2Constants {

        /**
         * The authorize endpoint for Google.
         */
        AUTHORIZE_URI_TEMPLATE("https://accounts.google.com/o/oauth2/v2/auth?prompt=consent&access_type=offline&client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The profile endpoint for Google.
         */
        PROFILE_URI("https://www.googleapis.com/plus/v1/people/me"),

        /**
         * The authenticate endpoint for Google.
         */
        AUTHENTICATE_URI("https://www.googleapis.com/oauth2/v4/token"),

        /**
         * The scope required for Google.
         */
        REQUIRED_SCOPES("email"),

        /**
         * The scope delimiter for Google.
         */
        SCOPE_DELIMITER("+"),

        /**
         * The relay key for Google.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("google"),

        /**
         * The implementation host.
         */
        HOST_GOOGLE("googleapis.com");

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
        private GoogleOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Contains caldav constants used in this implementation.
     */
    public enum GoogleCaldavConstants {

        HOST("apidata.googleusercontent.com"),
        DS_POLLING_INTERVAL("1m"),
        DS_PORT("443"),
        DS_CONNECTION_TYPE("ssl"),
        DS_ATTR_VAL("p:/caldav/v2/_USERNAME_/user");

        private String constant;

        public String getValue() {
            return constant;
        }

        private GoogleCaldavConstants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a GoogleOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public GoogleOAuth2Handler(Configuration config) {
        super(config, GoogleOAuth2Constants.CLIENT_NAME.getValue(), GoogleOAuth2Constants.HOST_GOOGLE.getValue());
        authenticateUri = GoogleOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = GoogleOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = GoogleOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = GoogleOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = GoogleOAuth2Constants.RELAY_KEY.getValue();
        dataSource.addImportClass(DataSourceType.oauth2contact.name(),
            GoogleContactsImport.class.getCanonicalName());
        dataSource.addImportClass(DataSourceType.oauth2caldav.name(),
            CalDavOAuth2DataImport.class.getCanonicalName());

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
            switch (GoogleErrorConstants.fromString(error.toUpperCase())) {
            case RESPONSE_ERROR_INVALID_REDIRECT_URI:
                ZimbraLog.extensions.info(
                    "Redirect does not match the one found in authorization request: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Redirect does not match the one found in authorization request.");
            case RESPONSE_ERROR_INVALID_AUTHORIZATION_CODE:
            case RESPONSE_ERROR_INVALID_GRANT:
                ZimbraLog.extensions
                    .debug("Invalid authorization / refresh token used: " + errorMsg);
                throw ServiceException.PERM_DENIED(
                    "Authorization or refresh token is expired or invalid. Unable to authenticate the user.");
            case RESPONSE_ERROR_UNSUPPORTED_GRANT_TYPE:
                ZimbraLog.extensions.debug("Unsupported grant type used: " + errorMsg);
                throw ServiceException.OPERATION_DENIED(
                    "Unsupported grant type used. Unable to authenticate the user.");
            case RESPONSE_ERROR_INVALID_CLIENT:
                ZimbraLog.extensions.warn(
                    "Invalid client or client secret provided to the social service: " + errorMsg);
                throw ServiceException
                    .OPERATION_DENIED("Invalid client details provided to the social service.");
            case RESPONSE_ERROR_INVALID_REQUEST:
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

    @Override
    protected Map<String, Object> getDatasourceCustomAttrs(OAuthInfo oauthInfo) throws ServiceException {
        final String type = oauthInfo.getParam("type");
        final Map<String, Object> dsAttrs = new HashMap<String, Object>();
        if (DataSourceType.oauth2caldav == OAuth2DataSource.getDataSourceTypeForOAuth2(type)) {
            final String[] dsAttrArr = new String[] {GoogleCaldavConstants.DS_ATTR_VAL.getValue()};
            dsAttrs.put(Provisioning.A_zimbraDataSourcePort, GoogleCaldavConstants.DS_PORT.getValue());
            dsAttrs.put(Provisioning.A_zimbraDataSourceConnectionType, GoogleCaldavConstants.DS_CONNECTION_TYPE.getValue());
            dsAttrs.put(Provisioning.A_zimbraDataSourceAttribute, dsAttrArr);
            dsAttrs.put(Provisioning.A_zimbraDataSourcePollingInterval, GoogleCaldavConstants.DS_POLLING_INTERVAL.getValue());
            dsAttrs.put(Provisioning.A_zimbraDataSourceHost, GoogleCaldavConstants.HOST.getValue());
            dsAttrs.put(Provisioning.A_zimbraDataSourceUsername, oauthInfo.getUsername());
        }
        return dsAttrs;
    }

}
