package com.zimbra.oauth.utilities;

public class OAuth2Constants {
	public static final String API_NAME = "zm-oauth2";
	public static final String ENCODING = "utf-8";
	public static final String DEFAULT_LOG_LEVEL = "INFO";
	public static final Integer DEFAULT_SERVER_PORT = 8080;
	public static final String DEFAULT_SERVER_CONTEXT_PATH = "/*";

	public static final String OAUTH2_RELAY_KEY = "state";
	public static final String DEFAULT_SUCCESS_REDIRECT = "/";
	public static final String DEFAULT_HOST_URI_TEMPLATE = "https://%s:443";

	// http related
	public static final String HEADER_LOCATION = "Location";
	public static final String QUERY_ERROR = "error";
	public static final String QUERY_ERROR_MSG = "error_msg";

	// http query error related
	public static final String ERROR_ACCESS_DENIED = "access_denied";
	public static final String ERROR_INVALID_AUTH_CODE = "invalid_auth_code";
	public static final String ERROR_INVALID_ZM_AUTH_CODE = "invalid_zm_auth_code";
	public static final String ERROR_INVALID_ZM_AUTH_CODE_MSG = "Invalid or missing Zimbra session.";
	public static final String ERROR_AUTHENTICATION_ERROR = "authentication_error";

	// properties related
	public static final String PROPERTIES_NAME_APPLICATION = "application";

	// LC properties related
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
	// LC Yahoo
	public static final String LC_OAUTH_YAHOO_AUTHORIZE_URI_TEMPLATE = "zm_oauth_yahoo_authorize_uri_template";
	public static final String LC_OAUTH_YAHOO_PROFILE_URI_TEMPLATE = "zm_oauth_yahoo_profile_uri_template";
	public static final String LC_OAUTH_YAHOO_AUTHENTICATE_URI = "zm_oauth_yahoo_authenticate_uri";
	public static final String LC_OAUTH_YAHOO_CLIENT_ID = "zm_oauth_yahoo_client_id";
	public static final String LC_OAUTH_YAHOO_CLIENT_SECRET = "zm_oauth_yahoo_client_secret";
	public static final String LC_OAUTH_YAHOO_CLIENT_REDIRECT_URI = "zm_oauth_yahoo_client_redirect_uri";
	public static final String LC_OAUTH_YAHOO_IMPORT_CLASS = "zm_oauth_yahoo_import_class";
	public static final String LC_OAUTH_YAHOO_RELAY_KEY = "zm_oauth_yahoo_relay_key";
	// LC Google
	public static final String LC_OAUTH_GOOGLE_AUTHORIZE_URI_TEMPLATE = "zm_oauth_google_authorize_uri_template";
	public static final String LC_OAUTH_GOOGLE_PROFILE_URI_TEMPLATE = "zm_oauth_google_profile_uri_template";
	public static final String LC_OAUTH_GOOGLE_AUTHENTICATE_URI = "zm_oauth_google_authenticate_uri";
	public static final String LC_OAUTH_GOOGLE_CLIENT_ID = "zm_oauth_google_client_id";
	public static final String LC_OAUTH_GOOGLE_CLIENT_SECRET = "zm_oauth_google_client_secret";
	public static final String LC_OAUTH_GOOGLE_CLIENT_REDIRECT_URI = "zm_oauth_google_client_redirect_uri";
	public static final String LC_OAUTH_GOOGLE_SCOPE = "zm_oauth_google_scope";
	public static final String LC_OAUTH_GOOGLE_IMPORT_CLASS = "zm_oauth_google_import_class";
	public static final String LC_OAUTH_GOOGLE_RELAY_KEY = "zm_oauth_google_relay_key";
	// LC Outlook
	public static final String LC_OAUTH_OUTLOOK_AUTHORIZE_URI_TEMPLATE = "zm_oauth_outlook_authorize_uri_template";
	public static final String LC_OAUTH_OUTLOOK_PROFILE_URI_TEMPLATE = "zm_oauth_outlook_profile_uri_template";
	public static final String LC_OAUTH_OUTLOOK_AUTHENTICATE_URI = "zm_oauth_outlook_authenticate_uri";
	public static final String LC_OAUTH_OUTLOOK_CLIENT_ID = "zm_oauth_outlook_client_id";
	public static final String LC_OAUTH_OUTLOOK_CLIENT_SECRET = "zm_oauth_outlook_client_secret";
	public static final String LC_OAUTH_OUTLOOK_CLIENT_REDIRECT_URI = "zm_oauth_outlook_client_redirect_uri";
	public static final String LC_OAUTH_OUTLOOK_SCOPE = "zm_oauth_outlook_scope";
	public static final String LC_OAUTH_OUTLOOK_IMPORT_CLASS = "zm_oauth_outlook_import_class";
	public static final String LC_OAUTH_OUTLOOK_RELAY_KEY = "zm_oauth_outlook_relay_key";

	// ZDataSource temporary constant
	public static final String HOST_GOOGLE = "googleapis.com";
	public static final String HOST_OUTLOOK = "microsoftonline.com";
}
