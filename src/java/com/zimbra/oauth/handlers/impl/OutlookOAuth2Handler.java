package com.zimbra.oauth.handlers.impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.message.BasicNameValuePair;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.UserForbiddenException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthDataSource;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

public class OutlookOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

	/**
	 * The authorize endpoint for Outlook.
	 */
	protected final String authorizeUriTemplate;

	/**
	 * The authenticate endpoint for Outlook.
	 */
	protected final String authenticateUri;

	/**
	 * The profile endpoint for Outlook.
	 */
	protected final String profileUriTemplate;

	/**
	 * Outlook client id.
	 */
	protected final String clientId;

	/**
	 * Outlook client secret.
	 */
	protected final String clientSecret;

	/**
	 * Outlook redirect uri.
	 */
	protected final String clientRedirectUri;

	/**
	 * Default outlook relay key.
	 */
	protected final String relayKey;

	/**
	 * Outlook token scope.
	 */
	protected final String scope;

	/**
	 * DataSource handler for Outlook.
	 */
	protected final OAuthDataSource dataSource;

	/**
	 * Invalid request error from Outlook.<br>
	 * Protocol error, such as a missing required parameter.
	 */
	protected static final String RESPONSE_ERROR_INVALID_REQUEST = "invalid_request";

	/**
	 * Unauthorized client error from Outlook.<br>
	 * The client application is not permitted to request an authorization code.
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
	 * The target resource is invalid because it does not exist, Azure AD cannot find it, or it is not correctly configured.
	 */
	protected static final String RESPONSE_ERROR_INVALID_RESOURCE = "invalid_resource";

	/**
	 * Unsupported response type error from Outlook.<br>
	 * The authorization server does not support the response type in the request.
	 */
	protected static final String RESPONSE_ERROR_RESPONSE_TYPE = "unsupported_response_type";

	/**
	 * Constructs an OutlookOAuth2Handler object.
	 *
	 * @param config For accessing configured properties
	 */
	public OutlookOAuth2Handler(Configuration config) {
		super(config);
		authorizeUriTemplate = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_AUTHORIZE_URI_TEMPLATE);
		authenticateUri = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_AUTHENTICATE_URI);
		profileUriTemplate = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_PROFILE_URI_TEMPLATE);
		clientId = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_ID);
		clientSecret = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_SECRET);
		clientRedirectUri = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_REDIRECT_URI);
		relayKey = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_RELAY_KEY, OAuth2Constants.OAUTH2_RELAY_KEY);
		scope = config.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_SCOPE);
		dataSource = new OAuthDataSource(OAuth2Constants.HOST_OUTLOOK);
	}

	@Override
	public String authorize(String relayState) throws GenericOAuthException {
		final String responseType = "code";
		String encodedRedirectUri = "";
		try {
			encodedRedirectUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);
		} catch (final UnsupportedEncodingException e) {
			ZimbraLog.extensions.error("Invalid redirect URI found in client config.", e);
			throw new ConfigurationException("Invalid redirect URI found in client config.");
		}

		String relayParam = "%s";
		String relayValue = "";
		String relay = StringUtils.defaultString(relayState, "");

		if (!relay.isEmpty()) {
			try {
				relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING);
			} catch (final UnsupportedEncodingException e) {
				throw new InvalidOperationException("Unable to decode relay parameter.");
			}

			try {
				relayParam = "&" + relayKey + "=%s";
				relayValue = URLEncoder.encode(relay, OAuth2Constants.ENCODING);
			} catch (final UnsupportedEncodingException e) {
				throw new InvalidOperationException("Unable to encode relay parameter.");
			}
		}
		return String.format(authorizeUriTemplate + relayParam, clientId, encodedRedirectUri, responseType, relayValue, scope);
	}

	@Override
	public Boolean authenticate(OAuthInfo oauthInfo) throws GenericOAuthException {
		oauthInfo.setClientId(clientId);
		oauthInfo.setClientSecret(clientSecret);
		final HttpClientContext context = HttpClientContext.create();
		final JsonNode credentials = authenticateRequest(oauthInfo, clientRedirectUri, context);

		// get zimbra mailbox
		final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

		// store username, zimbraAccountId, refreshToken
		oauthInfo.setUsername(getPrimaryEmail(credentials));
		oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
		dataSource.updateCredentials(mailbox, oauthInfo);
		return true;
	}

	@Override
	public Boolean refresh(OAuthInfo oauthInfo) throws GenericOAuthException {
		oauthInfo.setClientId(clientId);
		oauthInfo.setClientSecret(clientSecret);
		final HttpClientContext context = HttpClientContext.create();

		// get zimbra mailbox
		final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

		// get refreshToken from DataSource with end service username (user@outlook.com)
		final String refreshToken = dataSource.getRefreshToken(mailbox, oauthInfo.getUsername());

		// invalid operation if no refresh token stored for the user
		if (StringUtils.isEmpty(refreshToken)) {
			throw new InvalidOperationException("The specified user has no stored refresh token.");
		}

		// add refreshToken to oauthInfo, call authenticateRequest
		oauthInfo.setRefreshToken(refreshToken);
		final JsonNode credentials = authenticateRequest(oauthInfo, clientRedirectUri, context);

		// update credentials
		oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
		dataSource.updateCredentials(mailbox, oauthInfo);
		return true;
	}

	protected JsonNode authenticateRequest(OAuthInfo authInfo, String redirectUri, HttpClientContext context) throws GenericOAuthException {
		final String clientId = authInfo.getClientId();
		final String clientSecret = authInfo.getClientSecret();
		final String basicToken = Base64.encodeBase64String(new String(clientId + ":" + clientSecret).getBytes());
		final String code = authInfo.getCode();
		final String refreshToken = authInfo.getRefreshToken();
		final HttpPost request = new HttpPost(authenticateUri);
		final List<NameValuePair> params = new ArrayList<NameValuePair>();
		if (!StringUtils.isEmpty(refreshToken)) {
			// set refresh token if we have one
			params.add(new BasicNameValuePair("grant_type", "refresh_token"));
			params.add(new BasicNameValuePair("refresh_token", refreshToken));
		} else {
			// otherwise use the code
			params.add(new BasicNameValuePair("grant_type", "authorization_code"));
			params.add(new BasicNameValuePair("code", code));
		}
		params.add(new BasicNameValuePair("redirect_uri", redirectUri));
		params.add(new BasicNameValuePair("client_secret", clientSecret));
		params.add(new BasicNameValuePair("client_id", clientId));
		request.setHeader("Content-Type", "application/x-www-form-urlencoded");
		request.setHeader("Authorization", "Basic " + basicToken);
		JsonNode json = null;
		try {
			request.setEntity(new UrlEncodedFormEntity(params));
			json = executeRequest(request, context);
		} catch (final IOException e) {
			ZimbraLog.extensions.error("There was an issue acquiring the authorization token.", e);
			throw new UserUnauthorizedException("There was an issue acquiring an authorization token for this user.");
		}

		// ensure the response contains the necessary credentials
		validateAuthenticateResponse(json);

		return json;
	}

	/**
	 * Validates that the response from authenticate has no errors, and contains the
	 * requested access information.
	 *
	 * @param response The json response from authenticate
	 * @throws InvalidOperationException If the refresh token was deemed invalid, or incorrect redirect uri
	 * @throws UserUnauthorizedException If the refresh token or code is expired, or for general rejection
	 * @throws UserForbiddenException If the user did not provide authorization for the same client Id used in the authenticate
	 * @throws InvalidResponseException If the response from Outlook has no errors, but the access info is missing
	 * @throws ConfigurationException If the client id or client secret are incorrect
	 * @throws GenericOAuthException If there are issues with the response
	 */
	protected void validateAuthenticateResponse(JsonNode response) throws GenericOAuthException {
		// check for errors
		if (response.has("error")) {
			final String error = response.get("error").asText();
			final JsonNode errorMsg = response.get("error_description");
			switch (error) {
				case RESPONSE_ERROR_INVALID_REQUEST:
					ZimbraLog.extensions.warn("Invalid authentication request parameters: " + errorMsg);
					throw new InvalidOperationException("The authentication request parameters are invalid.");
				case RESPONSE_ERROR_UNAUTHORIZED_CLIENT:
					ZimbraLog.extensions.warn("The specified client details provided to oauth2 server are invalid: " + errorMsg );
					throw new ConfigurationException("The specified client details provided to oauth2 server are invalid.");
				case RESPONSE_ERROR_ACCESS_DENIED:
					ZimbraLog.extensions.info("User did not provide authorization for this service: " + errorMsg);
					throw new UserForbiddenException("User did not provide authorization for this service.");
				case RESPONSE_ERROR_SERVER_ERROR:
				case RESPONSE_ERROR_TEMPORARILY_UNAVAILABLE:
					ZimbraLog.extensions.debug("There was an issue with the remote oauth2 server: " + errorMsg);
					throw new InvalidResponseException("There was an issue with the remote oauth2 server.");
				case RESPONSE_ERROR_INVALID_RESOURCE:
					ZimbraLog.extensions.debug("Invalid resource: " + errorMsg);
					throw new UserUnauthorizedException("The specified resource is invalid.");
				case RESPONSE_ERROR_RESPONSE_TYPE:
					ZimbraLog.extensions.info("Requested response type is not supported: " + errorMsg);
					throw new InvalidOperationException("Requested response type is not supported by the oauth2 server.");
				default:
					ZimbraLog.extensions.warn("Unexpected error while trying to authenticate the user: " + errorMsg);
					throw new UserUnauthorizedException("Unable to authenticate the user.");
			}
		}

		// ensure the tokens we requested are present
		if (!response.has("access_token") || !response.has("refresh_token")) {
			throw new InvalidResponseException("Unexpected response from mail server.");
		}
	}

	/**
	 * Retrieves the user's email address.
	 *
	 * @param credentials The json response from token call
	 * @return The primary email address for the user
	 * @throws InvalidResponseException If the email address is missing
	 */
	protected String getPrimaryEmail(JsonNode credentials) throws InvalidResponseException {
		final DecodedJWT jwt = JWT.decode(credentials.get("id_token").asText());
		final Claim emailClaim = jwt.getClaim("email");
		if (emailClaim == null) {
			throw new InvalidResponseException("Authentication response is missing primary email.");
		}
		ZimbraLog.extensions.debug(jwt.getClaim("email").asString());
		return jwt.getClaim("email").asString();
	}

}
