package com.zimbra.oauth.utilities;

public class OAuth2Constants {
	public static final String API_NAME = "zm-oauth2";
	public static final String ENCODING = "utf-8";
	public static final String DEFAULT_LOG_LEVEL = "INFO";
	public static final Integer DEFAULT_SERVER_PORT = 8080;
	public static final String DEFAULT_SERVER_CONTEXT_PATH = "/";

	public static final String OAUTH2_RELAY_KEY = "";
	public static final String DEFAULT_SUCCESS_REDIRECT = "/";

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

}
