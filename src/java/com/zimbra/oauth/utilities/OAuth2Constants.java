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
public class OAuth2Constants {

    public static final String API_NAME = "zm-oauth-social";
    public static final String ENCODING = "utf-8";
    public static final String DEFAULT_SERVER_PATH = "/oauth2";

    public static final String OAUTH2_RELAY_KEY = "state";
    public static final String DEFAULT_SUCCESS_REDIRECT = "/";
    public static final String DEFAULT_HOST_URI_TEMPLATE = "https://%s:443";
    public static final String DEFAULT_OAUTH_FOLDER_TEMPLATE = "%s-%s";

    // http related
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_CONTENT_TYPE = "Content-Type";
    public static final String HEADER_ACCEPT = "Accept";
    public static final String HEADER_LOCATION = "Location";
    public static final String QUERY_ERROR = "error";
    public static final String QUERY_ERROR_MSG = "error_msg";
    public static final String COOKIE_AUTH_TOKEN = "ZM_AUTH_TOKEN";

    public static final String PROPERTIES_NAME_APPLICATION = "application";

    // http query error related
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    public static final String ERROR_INVALID_AUTH_CODE = "invalid_auth_code";
    public static final String ERROR_INVALID_ZM_AUTH_CODE = "invalid_zm_auth_code";
    public static final String ERROR_INVALID_ZM_AUTH_CODE_MSG = "Invalid or missing Zimbra session.";
    public static final String ERROR_AUTHENTICATION_ERROR = "authentication_error";
    public static final String ERROR_UNHANDLED_ERROR = "unhandled_error";

    // LC properties related
    public static final String LC_ZIMBRA_SERVER_HOSTNAME = "zimbra_server_hostname";
    public static final String LC_HANDLER_CLASS_PREFIX = "zm_oauth_classes_handlers_";
    public static final String LC_SOAP_HOST = "soap_host";
    public static final String LC_HOST_URI_TEMPLATE = "host_uri_template";

    public static final String LC_OAUTH_CLIENT_ID_TEMPLATE = "zm_oauth_%s_client_id";
    public static final String LC_OAUTH_CLIENT_SECRET_TEMPLATE = "zm_oauth_%s_client_secret";
    public static final String LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE = "zm_oauth_%s_client_redirect_uri";
    public static final String LC_OAUTH_SCOPE_TEMPLATE = "zm_oauth_%s_scope";
    public static final String LC_OAUTH_IMPORT_CLASS_TEMPLATE = "zm_oauth_%s_import_class";

}
