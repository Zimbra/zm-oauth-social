package com.zimbra.oauth.handlers.impl;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
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
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.ServiceNotAvailableException;
import com.zimbra.oauth.exceptions.UnreachableHostException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

public class OAuth2Handler {

	protected static final Map<String, CloseableHttpClient> clients = Collections.synchronizedMap(new HashMap<String, CloseableHttpClient>(1));

	protected final CloseableHttpClient client;

	protected final Configuration config;

	protected static final ObjectMapper mapper = OAuth2Utilities.createDefaultMapper();

	protected final String zimbraHostUri;

	protected final String storageFolderId;

	public OAuth2Handler(Configuration config) {
		this.config = config;
		client = buildHttpClientIfAbsent(config);

		synchronized (LC.zimbra_server_hostname) {
			final String zimbraHostname = LC.zimbra_server_hostname.value();
			// warn if missing hostname
			if (StringUtils.isEmpty(zimbraHostname)) {
				ZimbraLog.extensions.warn("The zimbra server hostname is not configured.");
			}
			// cache the host uri
			zimbraHostUri = String.format(
				config.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE, OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE),
				zimbraHostname
			);
			// set the zmprov soap server
			LC.zimbra_zmprov_default_soap_server.setDefault(zimbraHostname);
			LC.ssl_allow_accept_untrusted_certs.setDefault("true");
			LC.ssl_allow_untrusted_certs.setDefault("true");
		}
		storageFolderId = config.getString(OAuth2Constants.LC_OAUTH_FOLDER_ID);
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
	protected JsonNode executeRequest(HttpUriRequest request, HttpClientContext context) throws GenericOAuthException, IOException {
		CloseableHttpResponse response = null;
		JsonNode json = null;
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

		// try to parse json
		// throw if the upstream response
		// is not what we previously expected
		try {
			ZimbraLog.extensions.debug(responseBody);
			json = mapper.readTree(responseBody);
		} catch (final JsonParseException e) {
			ZimbraLog.extensions.warn("The destination server responded with unexpected data.", e);
			throw new InvalidResponseException("The destination server responded with unexpected data.");
		}

		return json;
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
