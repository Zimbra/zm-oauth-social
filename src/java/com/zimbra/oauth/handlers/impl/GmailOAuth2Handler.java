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

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

public class GmailOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

	protected final String authorizeUriTemplate;

	protected final String authenticateUri;

	public GmailOAuth2Handler(Configuration config) {
		super(config);
		authorizeUriTemplate = config.getString("http.authorize.uri.template");
		authenticateUri = config.getString("http.authenticate.uri");
	}

	@Override
	public String authorize(String relayState) throws GenericOAuthException {
		final String clientId = config.getString("oauth.clientid");
		final String responseType = "code";
		String redirectUri = "";
		try {
			redirectUri = URLEncoder.encode(config.getString("oauth.redirecturi"), OAuth2Constants.ENCODING);
		} catch (final UnsupportedEncodingException e) {
			ZimbraLog.extensions.error("Invalid redirect URI found in client config.", e);
			throw new ConfigurationException("Invalid redirect URI found in client config.");
		}

		String relayParam = "%s";
		String relayValue = "";
		final String stateKey = StringUtils.defaultString(config.getString("oauth.relaykey"),
				OAuth2Constants.OAUTH2_RELAY_KEY);
		String relay = StringUtils.defaultString(relayState, "");

		if (!relay.isEmpty()) {
			try {
				relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING);
			} catch (final UnsupportedEncodingException e) {
				throw new InvalidOperationException("Unable to decode relay parameter.");
			}

			try {
				relayParam = "&" + stateKey + "=%s";
				relayValue = URLEncoder.encode(relay, OAuth2Constants.ENCODING);
			} catch (final UnsupportedEncodingException e) {
				throw new InvalidOperationException("Unable to encode relay parameter.");
			}
		}
		return String.format(authorizeUriTemplate + relayParam, clientId, redirectUri, responseType, relayValue);
	}

	@Override
	public Boolean authenticate(OAuthInfo oauthInfo) throws GenericOAuthException {
		final String redirectUri = config.getString("oauth.redirecturi");
		final HttpClientContext context = HttpClientContext.create();
		authenticateRequest(oauthInfo, redirectUri, context);

		//TODO: fix up the oauthInfo

		//TODO: use ephemeral-storage

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

	protected void validateAuthenticateResponse(JsonNode response) throws GenericOAuthException {
		// check for errors
		if (response.has("error")) {

		}

		// TODO
	}

	@Override
	public Boolean refresh(String client, String username) throws GenericOAuthException {
		// TODO Auto-generated method stub
		return null;
	}

}
