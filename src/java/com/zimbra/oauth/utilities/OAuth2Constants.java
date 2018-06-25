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
package com.zimbra.oauth.utilities;

/**
 * The OAuth2Constants class.<br>
 * OAuth2Constants contains constants used in the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public enum OAuth2Constants {

    API_NAME("zm-oauth-social"),
    ENCODING("utf-8"),
    DEFAULT_SERVER_PATH("/oauth2"),

    OAUTH2_RELAY_KEY("state"),
    DEFAULT_SUCCESS_REDIRECT("/"),
    DEFAULT_HOST_URI_TEMPLATE("https://%s:443"),
    DEFAULT_OAUTH_FOLDER_TEMPLATE("%s-%s"),

    DATASOURCE_POLLING_INTERVAL("1d"),

    CONTACTS_IMAGE_BUFFER_SIZE("2048"),

    // http related
    HEADER_AUTHORIZATION("Authorization"),
    HEADER_CONTENT_TYPE("Content-Type"),
    HEADER_ACCEPT("Accept"),
    HEADER_LOCATION("Location"),
    QUERY_ERROR("error"),
    QUERY_ERROR_MSG("error_msg"),
    COOKIE_AUTH_TOKEN("ZM_AUTH_TOKEN"),

    PROPERTIES_NAME_APPLICATION("application"),

    // http query error related
    ERROR_ACCESS_DENIED("access_denied"),
    ERROR_INVALID_AUTH_CODE("invalid_auth_code"),
    ERROR_INVALID_ZM_AUTH_CODE("invalid_zm_auth_code"),
    ERROR_INVALID_ZM_AUTH_CODE_MSG("Invalid or missing Zimbra session."),
    ERROR_AUTHENTICATION_ERROR("authentication_error"),
    ERROR_UNHANDLED_ERROR("unhandled_error"),
    ERROR_TYPE_MISSING("missing_type"),

    // LC properties related
    LC_ZIMBRA_SERVER_HOSTNAME("zimbra_server_hostname"),
    LC_HANDLER_CLASS_PREFIX("zm_oauth_classes_handlers_"),
    LC_SOAP_HOST("soap_host"),
    LC_HOST_URI_TEMPLATE("host_uri_template"),

    LC_OAUTH_CLIENT_ID_TEMPLATE("zm_oauth_%s_client_id"),
    LC_OAUTH_CLIENT_SECRET_TEMPLATE("zm_oauth_%s_client_secret"),
    LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE("zm_oauth_%s_client_redirect_uri"),
    LC_OAUTH_SCOPE_TEMPLATE("zm_oauth_%s_scope"),
    LC_OAUTH_IMPORT_CLASS_TEMPLATE("zm_oauth_%s_import_class"),


    OAUTH_CLIENT_ID("client_id"),
    OAUTH_CLIENT_SECRET("client_secret"),
    OAUTH_CLIENT_REDIRECT_URI("client_redirect_uri"),
    OAUTH_SCOPE("scope"),

    TYPE_KEY("type");

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
    private OAuth2Constants(String constant) {
        this.constant = constant;
    }
}
