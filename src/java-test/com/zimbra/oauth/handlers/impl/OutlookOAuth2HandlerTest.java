package com.zimbra.oauth.handlers.impl;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.client.ZMailbox;
import com.zimbra.oauth.models.OAuthDataSource;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * Test class for {@link OutlookOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({HttpClientContext.class, OAuthDataSource.class, OAuth2Handler.class, OutlookOAuth2Handler.class, ZMailbox.class})
@SuppressStaticInitializationFor("com.zimbra.client.ZMailbox")
public class OutlookOAuth2HandlerTest {

	/**
	 * Class under test.
	 */
	protected OutlookOAuth2Handler handler;

	/**
	 * Mock client handler property.
	 */
	protected CloseableHttpClient mockClient = EasyMock.createMock(CloseableHttpClient.class);

	/**
	 * Mock configuration handler property.
	 */
	protected Configuration mockConfig = EasyMock.createMock(Configuration.class);

	/**
	 * Mock data source handler property.
	 */
	protected OAuthDataSource mockDataSource = EasyMock.createMock(OAuthDataSource.class);

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
	 * FolderId for testing.
	 */
	protected final String storageFolderId = "259";

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		handler = PowerMock
			.createPartialMockForAllMethodsExcept(OutlookOAuth2Handler.class, "authorize", "authenticate");
		Whitebox.setInternalState(handler, "clientRedirectUri", clientRedirectUri);
		Whitebox.setInternalState(handler, "authorizeUriTemplate", "%s %s %s");
		Whitebox.setInternalState(handler, "clientId", clientId);
		Whitebox.setInternalState(handler, "clientSecret", clientSecret);
		Whitebox.setInternalState(handler, "dataSource", mockDataSource);
		Whitebox.setInternalState(handler, "storageFolderId", storageFolderId);

		expect(mockConfig.getClientId()).andReturn(clientId);

		// use mock http client for test client
		final Map<String, CloseableHttpClient> clients = new HashMap<String, CloseableHttpClient>(1);
		clients.put(clientId, mockClient);
		Whitebox.setInternalState(OutlookOAuth2Handler.class, "clients", clients);
	}

	/**
	 * Test method for {@link OutlookOAuth2Handler#OutlookOAuth2Handler}<br>
	 * Validates that the constructor configured some necessary properties.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testOutlookOAuth2Handler() throws Exception {
		final OAuthDataSource mockDataSource = EasyMock.createMock(OAuthDataSource.class);

		expect(mockConfig.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE, OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE))
			.andReturn(OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_FOLDER_ID)).andReturn(storageFolderId);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_AUTHORIZE_URI_TEMPLATE)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_AUTHENTICATE_URI)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_PROFILE_URI_TEMPLATE)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_ID)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_SECRET)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_CLIENT_REDIRECT_URI)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_RELAY_KEY, OAuth2Constants.OAUTH2_RELAY_KEY)).andReturn(null);
		expect(mockConfig.getString(OAuth2Constants.LC_OAUTH_OUTLOOK_SCOPE)).andReturn(null);
		PowerMock.mockStatic(OAuthDataSource.class);
		expect(OAuthDataSource.createDataSource(OAuth2Constants.HOST_OUTLOOK)).andReturn(mockDataSource);

		replay(mockConfig);
		PowerMock.replay(OAuthDataSource.class);

		new OutlookOAuth2Handler(mockConfig);

		verify(mockConfig);
		PowerMock.verify(OAuthDataSource.class);
	}

	/**
	 * Test method for {@link OutlookOAuth2Handler#authorize}<br>
	 * Validates that the authorize method returns a location with an encoded redirect uri.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthorize() throws Exception {
		final String encodedUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);

		final String authorizeLocation = handler.authorize(null);

		assertNotNull(authorizeLocation);
		assertEquals(clientId + " " + encodedUri + " code", authorizeLocation);
	}

	/**
	 * Test method for {@link OutlookOAuth2Handler#authenticate}<br>
	 * Validates that the authenticate method calls update datasource.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticate() throws Exception {
		final String username = "test-user@localhost";
		final String refreshToken = "refresh-token";
		final String zmAuthToken = "zm-auth-token";
		final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
		final ZMailbox mockZMailbox = EasyMock.createMock(ZMailbox.class);
		final JsonNode mockCredentials = EasyMock.createMock(JsonNode.class);
		final JsonNode mockCredentialsRToken = EasyMock.createMock(JsonNode.class);

		expect(handler.getZimbraMailbox(anyObject(String.class))).andReturn(mockZMailbox);
		expect(handler.authenticateRequest(anyObject(OAuthInfo.class), matches(clientRedirectUri), anyObject(HttpClientContext.class))).andReturn(mockCredentials);
		expect(mockCredentials.get("refresh_token")).andReturn(mockCredentialsRToken);
		expect(mockCredentialsRToken.asText()).andReturn(refreshToken);

		expect(handler.getPrimaryEmail(anyObject(JsonNode.class))).andReturn(username);

		expect(mockOAuthInfo.getZmAuthToken()).andReturn(zmAuthToken);
		mockOAuthInfo.setClientId(matches(clientId));
		EasyMock.expectLastCall().once();
		mockOAuthInfo.setClientSecret(matches(clientSecret));
		EasyMock.expectLastCall().once();
		mockOAuthInfo.setUsername(username);
		EasyMock.expectLastCall().once();
		mockOAuthInfo.setRefreshToken(refreshToken);
		EasyMock.expectLastCall().once();
		mockDataSource.updateCredentials(mockZMailbox, mockOAuthInfo, storageFolderId);
		EasyMock.expectLastCall().once();

		replay(handler);
		replay(mockOAuthInfo);
		PowerMock.replay(HttpClientContext.class);
		replay(mockCredentials);
		replay(mockCredentialsRToken);
		replay(mockDataSource);

		handler.authenticate(mockOAuthInfo);

		verify(handler);
		verify(mockOAuthInfo);
		PowerMock.verify(HttpClientContext.class);
		verify(mockCredentials);
		verify(mockCredentialsRToken);
		verify(mockDataSource);
	}

}
