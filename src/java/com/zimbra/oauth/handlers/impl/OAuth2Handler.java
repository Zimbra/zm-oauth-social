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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.ServiceNotAvailableException;
import com.zimbra.oauth.exceptions.UnreachableHostException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The OAuth2Handler class.<br>
 * Base OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class OAuth2Handler {

	/**
	 * Map of HTTP clients.
	 */
	protected static final Map<String, CloseableHttpClient> clients = Collections.synchronizedMap(new HashMap<String, CloseableHttpClient>(1));

	/**
	 * HTTP client.
	 */
	protected final CloseableHttpClient client;

	/**
	 * Configuration object.
	 */
	protected final Configuration config;

	/**
	 * A mapper object that can convert between Java <-> JSON objects.
	 */
	protected static final ObjectMapper mapper = OAuth2Utilities.createDefaultMapper();

	/**
	 * A URI string for the Zimbra host.
	 */
	protected final String zimbraHostUri;

	/**
	 * A storage folder identifier string.
	 */
	protected final String storageFolderId;

	/**
	 * Constructor.
	 *
	 * @param config A configuration object
	 */
	public OAuth2Handler(Configuration config) {
		this.config = config;
		client = buildHttpClientIfAbsent(config);

		synchronized (OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME) {
			final String zimbraHostname = config.getString(OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME);
			// warn if missing hostname
			if (StringUtils.isEmpty(zimbraHostname)) {
				ZimbraLog.extensions.warn("The zimbra server hostname is not configured.");
			}
			// cache the host uri
			zimbraHostUri = String.format(
				config.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE, OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE),
				zimbraHostname
			);
		}
		storageFolderId = config.getString(OAuth2Constants.LC_OAUTH_FOLDER_ID);
	}

	/**
	 * Declares the query params to look for on oauth2 authenticate callback.<br>
	 * This method should be overriden if the implementing client uses different parameters.
	 *
	 * @see IOAuth2Handler#getAuthenticateParamKeys()
	 */
	public List<String> getAuthenticateParamKeys() {
		// code, error, state are default oauth2 keys
		return Arrays.asList("code", "error", "state");
	}

	/**
	 * Default param verifier. Ensures no `error`, and that `code` is passed in.<br>
	 * This method should be overriden if the implementing client expects different parameters.
	 *
	 * @see IOAuth2Handler#verifyAuthenticateParams()
	 */
	public void verifyAuthenticateParams(Map<String, String> params) throws GenericOAuthException {
		final String error = params.get("error");
		// check for errors
		if (!StringUtils.isEmpty(error)) {
			throw new UserUnauthorizedException(error);
		// ensure code exists
		} else if (!params.containsKey("code")) {
			throw new InvalidOperationException(OAuth2Constants.ERROR_INVALID_AUTH_CODE);
		}
	}

	/**
	 * Returns the relay state param for the client.<br>
	 * This method should be overriden if the implementing client uses a different key for relay.
	 *
	 * @see IOAuth2Handler#getRelay()
	 */
	public String getRelay(Map<String, String> params) {
		return params.get("state");
	}

	/**
	 * Executes an HttpUriRequest and parses for json.
	 *
	 * @param request Request to execute
	 * @param context The context to use when executing
	 * @return Json response
	 * @throws GenericOAuthException If there are issues with the connection
	 * @throws IOException If there are non connection related issues
	 */
	protected JsonNode executeRequestForJson(HttpUriRequest request, HttpClientContext context) throws GenericOAuthException, IOException {
		JsonNode json = null;
		final String responseBody = executeRequest(request, context);

		// try to parse json
		// throw if the upstream response
		// is not what we previously expected
		try {
			json = mapper.readTree(responseBody);
		} catch (final JsonParseException e) {
			ZimbraLog.extensions.warn("The destination server responded with unexpected data.", e);
			throw new InvalidResponseException("The destination server responded with unexpected data.");
		}

		return json;
	}

	/**
	 * Executes an HttpUriRequest and returns the response body.
	 *
	 * @param request Request to execute
	 * @param context The context to use when executing
	 * @return Response body as a string
	 * @throws GenericOAuthException If there are issues with the connection
	 * @throws IOException If there are non connection related issues
	 */
	protected String executeRequest(HttpUriRequest request, HttpClientContext context) throws GenericOAuthException, IOException {
		CloseableHttpResponse response = null;
		String responseBody = null;
		try {
			response = client.execute(request, context);
			final HttpEntity body = response.getEntity();
			responseBody = new String(OAuth2Utilities.decodeStream(body.getContent(), body.getContentLength()));
		} catch (final UnknownHostException e) {
			ZimbraLog.extensions.error("The configured destination address is unknown: " + request.getURI(), e);
			throw new UnreachableHostException("The configured destination address is unknown.");
		} catch (final SocketTimeoutException e) {
			ZimbraLog.extensions.warn("The destination server took too long to respond to our request.", e);
			throw new UnreachableHostException("The destination server took too long to respond to our request.");
		} catch (final ConnectionPoolTimeoutException e) {
			ZimbraLog.extensions.warn("Too many active HTTP client connections, not enough resources available.", e);
			throw new ServiceNotAvailableException("Too many active connections, not enough resources available.");
		} finally {
			if (response != null) {
				response.close();
			}
		}
		return responseBody;
	}

	/**
	 * Creates an http client that can be used by the app.
	 *
	 * @param config The config to load properties from
	 * @return A configured closeable http client
	 */
	protected CloseableHttpClient buildHttpClientIfAbsent(Configuration config) {
		final String clientId = config.getClientId();
		CloseableHttpClient localClient = clients.get(clientId);
		// do nothing if the client has already been set this
		// method is only run in the constructor which is
		// only run from a synchronized Manager#getInstance method
		if (localClient == null) {
			final PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager();
			// limit the authenticate route
			manager.setDefaultMaxPerRoute(config.getInt(OAuth2Constants.LC_OAUTH_HTTP_CLIENT_MAX_PER, 150));
			manager.setMaxTotal(config.getInt(OAuth2Constants.LC_OAUTH_HTTP_CLIENT_MAX_TOTAL, 500));

			final RequestConfig requestConfig = RequestConfig.custom()
				// timeout for getting an http client
				.setConnectionRequestTimeout(config.getInt(OAuth2Constants.LC_OAUTH_HTTP_CLIENT_TIMEOUT, 3000))
				// timeout for host to answer an http request
				.setConnectTimeout(config.getInt(OAuth2Constants.LC_OAUTH_HTTP_CLIENT_ANSWER_TIMEOUT, 6000)).build();

			// create a single instance of pooling http client
			localClient = HttpClientBuilder.create().setConnectionManager(manager)
					.setDefaultRequestConfig(requestConfig).build();
			// cache for other daos
			clients.put(clientId, localClient);
		}
		return localClient;
	}

	/**
	 * Retrieves the Zimbra mailbox via specified auth token.
	 *
	 * @param zmAuthToken The Zimbra auth token to identify the account with
	 * @return The Zimbra mailbox
	 * @throws UserUnauthorizedException If there is an issue retrieving the account mailbox
	 */
	protected ZMailbox getZimbraMailbox(String zmAuthToken) throws UserUnauthorizedException {
		// create a mailbox by auth token
		try {
			return ZMailbox.getByAuthToken(new ZAuthToken(zmAuthToken), zimbraHostUri, true, true);
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue acquiring the mailbox using the specified auth token.", e);
			throw new UserUnauthorizedException("There was an issue acquiring the mailbox using the specified auth token", e);
		}
	}
}
