package com.zimbra.oauth.handlers.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.matches;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZDataSource;
import com.zimbra.client.ZMailbox;
import com.zimbra.oauth.models.OAuthDataSource;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * Test class for {@link YahooOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({HttpClientContext.class, OAuth2Handler.class, SSLContext.class, YahooOAuth2Handler.class, ZMailbox.class})
public class YahooOAuth2HandlerTest {

	/**
	 * Class under test.
	 */
	protected YahooOAuth2Handler handler = Mockito.mock(YahooOAuth2Handler.class);

	/**
	 * Mock client handler property.
	 */
	protected CloseableHttpClient mockClient = Mockito.mock(CloseableHttpClient.class);

	/**
	 * Mock configuration handler property.
	 */
	protected Configuration mockConfig = Mockito.mock(Configuration.class);

	/**
	 * Mock data source handler property.
	 */
	protected OAuthDataSource mockDataSource = Mockito.mock(OAuthDataSource.class);

	/**
	 * ClientId for testing.
	 */
	protected final String clientId = "test-client";

	/**
	 * ClientSecret for testing.
	 */
	protected final String clientSecret = "test-secret";

	/**
	 * Redirect URI for testing.
	 */
	protected final String clientRedirectUri = "http://localhost/oauth2/authenticate";

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		Whitebox.setInternalState(handler, "clientRedirectUri", clientRedirectUri);
		Whitebox.setInternalState(handler, "authorizeUriTemplate", "%s %s %s");
		Whitebox.setInternalState(handler, "clientId", clientId);
		Whitebox.setInternalState(handler, "clientSecret", clientSecret);
		Whitebox.setInternalState(handler, "dataSource", mockDataSource);

		when(mockConfig.getClientId()).thenReturn(clientId);

		// mock static methods for SSLContext before mocking ZMailbox
		final SSLContext sslContext = PowerMockito.mock(SSLContext.class);
		final SSLSocketFactory sslSocketFactory = PowerMockito.mock(SSLSocketFactory.class);
		PowerMockito.mockStatic(SSLContext.class);
		PowerMockito.doReturn(sslContext).when(SSLContext.class);
		SSLContext.getInstance("TLS");
		PowerMockito.when(sslContext.getSocketFactory()).thenReturn(sslSocketFactory);

		// use mock http client for test client
		final Map<String, CloseableHttpClient> clients = new HashMap<String, CloseableHttpClient>(1);
		clients.put(clientId, mockClient);
		Whitebox.setInternalState(YahooOAuth2Handler.class, "clients", clients);
	}

	/**
	 * Test method for {@link YahooOAuth2Handler#YahooOAuth2Handler}<br>
	 * Validates that the constructor configured some necessary properties.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testYahooOAuth2Handler() throws Exception {
		final OAuthDataSource mockDataSource = Mockito.mock(OAuthDataSource.class);

		when(mockConfig.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE, OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE))
			.thenReturn(OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE);
		PowerMockito.whenNew(OAuthDataSource.class).withAnyArguments().thenReturn(mockDataSource);

		new YahooOAuth2Handler(mockConfig);

		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_AUTHORIZE_URI_TEMPLATE);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_AUTHENTICATE_URI);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_PROFILE_URI_TEMPLATE);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_CLIENT_ID);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_CLIENT_SECRET);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_CLIENT_REDIRECT_URI);
		verify(mockConfig).getString(OAuth2Constants.LC_OAUTH_YAHOO_RELAY_KEY, OAuth2Constants.OAUTH2_RELAY_KEY);
		PowerMockito.verifyNew(OAuthDataSource.class).withArguments(ZDataSource.SOURCE_HOST_YAHOO);
	}

	/**
	 * Test method for {@link YahooOAuth2Handler#authorize}<br>
	 * Validates that the authorize method returns a location with an encoded redirect uri.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthorize() throws Exception {
		final String encodedUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);

		when(handler.authorize(anyString())).thenCallRealMethod();

		final String authorizeLocation = handler.authorize(null);

		assertNotNull(authorizeLocation);
		assertEquals(clientId + " " + encodedUri + " code", authorizeLocation);
	}

	/**
	 * Test method for {@link YahooOAuth2Handler#authenticate}<br>
	 * Validates that the authenticate method calls update datasource.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticate() throws Exception {
		final String username = "test-user@localhost";
		final String accessToken = "access-token";
		final String refreshToken = "refresh-token";
		final Long expires = 50000L;
		final String guid = "guid";
		final OAuthInfo mockOAuthInfo = Mockito.mock(OAuthInfo.class);
		final ZMailbox mockZMailbox = Mockito.mock(ZMailbox.class);
		final JsonNode mockProfile = Mockito.mock(JsonNode.class);
		final JsonNode mockProfileValue = Mockito.mock(JsonNode.class);
		final JsonNode mockCredentials = Mockito.mock(JsonNode.class);
		final JsonNode mockCredentialsAToken = Mockito.mock(JsonNode.class);
		final JsonNode mockCredentialsGuid = Mockito.mock(JsonNode.class);
		final JsonNode mockCredentialsRToken = Mockito.mock(JsonNode.class);

		when(handler.authenticate(any(OAuthInfo.class))).thenCallRealMethod();
		when(handler.getZimbraMailbox(anyString())).thenReturn(mockZMailbox);
		when(handler.authenticateRequest(any(OAuthInfo.class), anyString(), any(HttpClientContext.class))).thenReturn(mockCredentials);
		when(mockCredentials.get("access_token")).thenReturn(mockCredentialsAToken);
		when(mockCredentialsAToken.asText()).thenReturn(accessToken);
		when(mockCredentials.get("xoauth_yahoo_guid")).thenReturn(mockCredentialsGuid);
		when(mockCredentialsGuid.asText()).thenReturn(guid);
		when(mockCredentials.get("expires_in")).thenReturn(mockCredentialsAToken);
		when(mockCredentialsAToken.asLong()).thenReturn(expires);
		when(mockCredentials.get("refresh_token")).thenReturn(mockCredentialsRToken);
		when(mockCredentialsRToken.asText()).thenReturn(refreshToken);

		when(handler.getUserProfile(anyString(), anyString(), any(HttpClientContext.class))).thenReturn(mockProfile);
		when(mockProfile.get("profile")).thenReturn(mockProfileValue);
		when(mockProfileValue.get("emails")).thenReturn(mockProfileValue);
		when(mockProfileValue.get(0)).thenReturn(mockProfileValue);
		when(mockProfileValue.get("handle")).thenReturn(mockProfileValue);
		when(mockProfileValue.asText()).thenReturn(username);
		PowerMockito.mockStatic(HttpClientContext.class);

		handler.authenticate(mockOAuthInfo);

		verify(mockOAuthInfo).setClientId(matches(clientId));
		verify(mockOAuthInfo).setClientSecret(matches(clientSecret));
		PowerMockito.verifyStatic();
		HttpClientContext.create();
		verify(handler).authenticateRequest(any(OAuthInfo.class), matches(clientRedirectUri), any(HttpClientContext.class));
		verify(handler).getUserProfile(matches(guid), matches(accessToken), any(HttpClientContext.class));
		verify(mockOAuthInfo).setUsername(username);
		verify(mockOAuthInfo).setRefreshToken(refreshToken);
		verify(mockDataSource).updateCredentials(mockZMailbox, mockOAuthInfo);
	}

}
