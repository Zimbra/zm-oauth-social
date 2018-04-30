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
	public static final String DEFAULT_OAUTH_FOLDER_PATH = "oauth-storage";

	// http related
	public static final String HEADER_LOCATION = "Location";
	public static final String QUERY_ERROR = "error";
	public static final String QUERY_ERROR_MSG = "error_msg";
	public static final String COOKIE_AUTH_TOKEN = "ZM_AUTH_TOKEN";

	// http query error related
	public static final String ERROR_ACCESS_DENIED = "access_denied";
	public static final String ERROR_INVALID_AUTH_CODE = "invalid_auth_code";
	public static final String ERROR_INVALID_ZM_AUTH_CODE = "invalid_zm_auth_code";
	public static final String ERROR_INVALID_ZM_AUTH_CODE_MSG = "Invalid or missing Zimbra session.";
	public static final String ERROR_AUTHENTICATION_ERROR = "authentication_error";

	// properties related
	public static final String PROPERTIES_NAME_APPLICATION = "application";

	// LC properties related
	public static final String LC_HANDLER_CLASS_PREFIX = "zm_oauth_classes_handlers_";
	public static final String LC_SOAP_HOST = "soap_host";
	public static final String LC_HOST_URI_TEMPLATE = "host_uri_template";
	public static final String LC_OAUTH_FOLDER_ID = "zm_oauth_source_folder_id";
	public static final String LC_OAUTH_SERVER_PORT = "zm_oauth_server_port";
	public static final String LC_OAUTH_SERVER_CONTEXT_PATH = "zm_oauth_server_context_path";
	public static final String LC_OAUTH_LOG_LEVEL = "zm_oauth_log_level";
	// LC HTTP Client
	public static final String LC_OAUTH_HTTP_CLIENT_MAX_PER = "zm_oauth_http_client_max_per";
	public static final String LC_OAUTH_HTTP_CLIENT_MAX_TOTAL = "zm_oauth_http_client_max_total";
	public static final String LC_OAUTH_HTTP_CLIENT_TIMEOUT = "zm_oauth_http_client_timeout";
	public static final String LC_OAUTH_HTTP_CLIENT_ANSWER_TIMEOUT = "zm_oauth_http_client_answer_timeout";

}
