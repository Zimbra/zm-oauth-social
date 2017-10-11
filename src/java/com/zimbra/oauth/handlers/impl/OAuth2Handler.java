package com.zimbra.oauth.handlers.impl;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.ServiceNotAvailableException;
import com.zimbra.oauth.exceptions.UnreachableHostException;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Utilities;

public class OAuth2Handler {

	protected static final Map<String, CloseableHttpClient> clients = Collections.synchronizedMap(new HashMap<String, CloseableHttpClient>(1));

	protected final CloseableHttpClient client;

	protected final Configuration config;

	protected static final ObjectMapper mapper = OAuth2Utilities.createDefaultMapper();

	public OAuth2Handler(Configuration config) {
		this.config = config;
		client = buildHttpClientIfAbsent(config);

		// set some required localconfig properties
		synchronized (LC.zimbra_server_hostname) {
			final String hostname = config.getString("zimbra.soaphost");
			LC.ldap_host.setDefault(config.getString("zimbra.ldaphost"));
			LC.ldap_port.setDefault(config.getInt("zimbra.ldapport"));
			LC.zimbra_ldap_password.setDefault(config.getString("zimbra.ldappassword"));
			LC.zimbra_zmprov_default_soap_server.setDefault(hostname);
			LC.zimbra_server_hostname.setDefault(hostname);
			LC.ssl_allow_accept_untrusted_certs.setDefault("true");
			LC.ssl_allow_untrusted_certs.setDefault("true");
		}
	}

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

	protected CloseableHttpClient buildHttpClientIfAbsent(Configuration config) {
		final String clientId = config.getClientId();
		CloseableHttpClient localClient = clients.get(clientId);
		// do nothing if the client has already been set this
		// method is only run in the constructor which is
		// only run from a synchronized Manager#getInstance method
		if (localClient == null) {
			final PoolingHttpClientConnectionManager manager = new PoolingHttpClientConnectionManager();
			// limit the authenticate route
			manager.setDefaultMaxPerRoute(config.getInt("http.client.max.per", 150));
			manager.setMaxTotal(config.getInt("http.client.max.total", 500));

			final RequestConfig requestConfig = RequestConfig.custom()
				// timeout for getting an http client
				.setConnectionRequestTimeout(config.getInt("http.client.timeout", 3000))
				// timeout for host to answer an http request
				.setConnectTimeout(config.getInt("http.client.answer.timeout", 6000)).build();

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
	 * @throws InvalidResponseException If there is an issue retrieving the account mailbox
	 */
	protected ZMailbox getZimbraMailbox(String zmAuthToken) throws InvalidResponseException {
		// create a mailbox by auth token then retrieve its accountId
		try {
			return ZMailbox.getByAuthToken(zmAuthToken, config.getString("zimbra.soapuri"));
		} catch (final ServiceException e) {
			ZimbraLog.extensions.error("There was an issue acquiring the account id.", e);
			throw new InvalidResponseException("There was an issue acquiring the account id.", e);
		}
	}
}
