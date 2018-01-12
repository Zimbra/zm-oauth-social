package com.zimbra.oauth.utilities;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.managers.ClassManager;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.models.ResponseObject;

public class OAuth2ResourceUtilities {

	/**
	 * Handles client manager acquisition for authorize call.
	 *
	 * @param client The client
	 * @param relay The relay state
	 * @return HTTP Response
	 * @throws GenericOAuthException If there are issues
	 */
	public static final Response authorize(String client, String relay) throws GenericOAuthException {
		final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
		final String authorizeEndpoint = oauth2Handler.authorize(relay);

		final Map<String, Object> headers = new HashMap<String, Object>();
		headers.put(OAuth2Constants.HEADER_LOCATION, authorizeEndpoint);

		return OAuth2Utilities.buildResponse(null, Status.SEE_OTHER, headers);
	}

	/**
	 * Handles client manager acquisition, and input organization for the authenticate call.
	 *
	 * @param client The client
	 * @param uriInfo The context
	 * @param zmAuthToken The Zimbra auth token
	 * @return HTTP Response
	 * @throws GenericOAuthException If there are issues
	 */
	public static Response authenticate(String client, UriInfo uriInfo, String zmAuthToken) throws GenericOAuthException {
		final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
		final Map<String, String> errorParams = new HashMap<String, String>();
		final Map<String, String> params = getParams(oauth2Handler.getAuthenticateParamKeys(), uriInfo);

		// verify the expected params exist, with no errors
		try {
			oauth2Handler.verifyAuthenticateParams(params);
		} catch (final UserUnauthorizedException e) {
			// if unauthorized, pass along the error message
			errorParams.put(OAuth2Constants.QUERY_ERROR, OAuth2Constants.ERROR_ACCESS_DENIED);
			errorParams.put(OAuth2Constants.QUERY_ERROR_MSG, e.getMessage());
		} catch (final InvalidOperationException e) {
			// if invalid op, pass along the error message
			errorParams.put(OAuth2Constants.QUERY_ERROR, e.getMessage());
		}

		if (errorParams.isEmpty()) {
			// if there is no zimbra auth code, the zimbra account cannot be identified
			// this happens if the request has no zimbra cookie identifying a session
			if (StringUtils.isEmpty(zmAuthToken)) {
				errorParams.put(OAuth2Constants.QUERY_ERROR, OAuth2Constants.ERROR_INVALID_ZM_AUTH_CODE);
				errorParams.put(OAuth2Constants.QUERY_ERROR_MSG, OAuth2Constants.ERROR_INVALID_ZM_AUTH_CODE_MSG);
			} else {
				try {
					// no errors and auth token exists
					// attempt to authenticate
					final OAuthInfo authInfo = new OAuthInfo(params);
					authInfo.setZmAuthToken(zmAuthToken);
					oauth2Handler.authenticate(authInfo);
				} catch (final UserUnauthorizedException e) {
					// unauthorized does not have an error message associated with it
					errorParams.put(OAuth2Constants.QUERY_ERROR, OAuth2Constants.ERROR_ACCESS_DENIED);
				} catch (final GenericOAuthException e) {
					errorParams.put(OAuth2Constants.QUERY_ERROR, OAuth2Constants.ERROR_AUTHENTICATION_ERROR);
					errorParams.put(OAuth2Constants.QUERY_ERROR_MSG, e.getMessage());
				}
			}
		}

		// validate relay, then add error params if there are any, then redirect
		final String relay = oauth2Handler.getRelay(params);
		final Map<String, Object> headers = new HashMap<String, Object>();
		headers.put(OAuth2Constants.HEADER_LOCATION, addQueryParams(getValidatedRelay(relay), errorParams));

		return OAuth2Utilities.buildResponse(null, Status.SEE_OTHER, headers);
	}

	public static Response refresh(String client, String username, String zmAuthToken) throws GenericOAuthException {
		final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
		final OAuthInfo authInfo = new OAuthInfo(null);
		authInfo.setClientId(client);
		authInfo.setUsername(username);
		authInfo.setZmAuthToken(zmAuthToken);
		return OAuth2Utilities.buildResponse(new ResponseObject<Boolean>(oauth2Handler.refresh(authInfo)), null, null);
	}

	/**
	 * Retrieves a map of query params expected for the client.
	 *
	 * @param expectedParams A list of params this client is looking for
	 * @param uriInfo The context to check for request params
	 * @return Map of params found
	 */
	private static Map<String, String> getParams(List<String> expectedParams, UriInfo uriInfo) {
		final Map<String, String> foundParams = new HashMap<String, String>(expectedParams.size());
		final MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();

		// check for every expected param, add if it exists
		for (final String key : expectedParams) {
			if (queryParams.containsKey(key)) {
				foundParams.put(key, queryParams.getFirst(key));
			}
		}

		return foundParams;
	}

	/**
	 * Returns a validated relative URI, or the default success redirect
	 * if no valid url was provided.
	 *
	 * @param url The url to validate
	 * @return relay A relative url
	 */
	private static String getValidatedRelay(String url) {
		String relay = OAuth2Constants.DEFAULT_SUCCESS_REDIRECT;

		if (!StringUtils.isEmpty(url)) {
			try {
				// if the url can be decoded and is relative, then set it as our relay
				final String decodedUrl = URLDecoder.decode(url, OAuth2Constants.ENCODING);
				if (!new URI(decodedUrl).isAbsolute()) {
					relay = decodedUrl;
				}
			} catch (final UnsupportedEncodingException e) {
				ZimbraLog.extensions.info("Unable to decode relay parameter.");
			} catch (final URISyntaxException e) {
				ZimbraLog.extensions.info("Invalid relay URI syntax found.");
			}
		}
		return relay;
	}

	/**
	 * Add query parameters to a path.<br>
	 * Empty path or param map results in no change.<br>
	 * Empty key or value params are ignored.
	 *
	 * @param path The path to add to
	 * @param params The params to add
	 * @return The path with added query parameters
	 */
	private static String addQueryParams(String path, Map<String, String> params) {
		// do nothing for empty path, or param map
		if (StringUtils.isEmpty(path) || params == null || params.size() < 1) {
			return path;
		}

		final UriBuilder pathUri = UriBuilder.fromPath(path);
		// add each param if the key and value are not empty
		for (final Entry<String, String> param : params.entrySet()) {
			final String key = param.getKey();
			final String value = param.getValue();
			if (!StringUtils.isEmpty(key) && !StringUtils.isEmpty(value)) {
				pathUri.queryParam(key, value);
			}
		}
		return pathUri.build().toString();
	}
}
