package com.zimbra.oauth.managers;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.apache.http.impl.client.CloseableHttpClient;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.zimbra.common.localconfig.KnownKey;
import com.zimbra.common.localconfig.LC;
import com.zimbra.oauth.exceptions.InvalidClientException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.handlers.impl.OAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * Test class for {@link ClassManager}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({CloseableHttpClient.class, ClassManager.class, Configuration.class, LC.class, OAuth2Handler.class})
@SuppressStaticInitializationFor("com.zimbra.common.localconfig.LC")
public class ClassManagerTest {

	/**
	 * Mock config for testing.
	 */
	protected Configuration mockConfig;

	/**
	 * Handler cache map for testing.
	 */
	protected final Map<String, IOAuth2Handler> handlerCacheMap = new HashMap<String, IOAuth2Handler>();

	/**
	 * Http client cache map for testing.
	 */
	protected final Map<String, CloseableHttpClient> httpClients = new HashMap<String, CloseableHttpClient>();

	/**
	 * Test client.
	 */
	protected final String client = "yahoo";

	/**
	 * Test folder id.
	 */
	protected final String folderId = "257";

	/**
	 * Test hostname.
	 */
	protected static final String hostname = "zcs-dev.test";

	/**
	 * Setup the static LC properties used during testing once.
	 *
	 * @throws Exception If there are issues during setup
	 */
	@BeforeClass
	public static void setUpOnce() throws Exception {
		PowerMock.mockStatic(LC.class);
		// set the LC keys that are used
		expect(LC.get(matches("zimbra_server_hostname"))).andReturn(hostname);
		final KnownKey hostnameKey = KnownKey.newKey(hostname);
		hostnameKey.setKey("zimbra_server_hostname");
		Whitebox.setInternalState(LC.class, "zimbra_server_hostname", hostnameKey);
		Whitebox.setInternalState(LC.class, "zimbra_zmprov_default_soap_server", KnownKey.newKey(hostname));
		Whitebox.setInternalState(LC.class, "ssl_allow_accept_untrusted_certs", KnownKey.newKey("true"));
		Whitebox.setInternalState(LC.class, "ssl_allow_untrusted_certs", KnownKey.newKey("true"));
	}

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		PowerMock.mockStatic(Configuration.class);

		// set the handler cache for reference during tests
		Whitebox.setInternalState(ClassManager.class, "handlersCache", handlerCacheMap);

		mockConfig = EasyMock.createMock(Configuration.class);

		// skip creating the http client
		httpClients.put(client, EasyMock.createMock(CloseableHttpClient.class));
		Whitebox.setInternalState(OAuth2Handler.class, "clients", httpClients);
	}

	/**
	 * Test method for {@link ClassManager#getHandler}<br>
	 * Validates that a client handler is created and cached.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testGetHandler() throws Exception {
		expect(Configuration.buildConfiguration(anyObject(String.class))).andReturn(mockConfig);
		expect(mockConfig.getString(matches("zm_oauth_classes_handlers_" + client)))
			.andReturn("com.zimbra.oauth.handlers.impl.YahooOAuth2Handler");
		expect(mockConfig.getClientId()).andReturn(client);
		expect(mockConfig.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE, OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE))
			.andReturn(OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE);
		expect(mockConfig.getString(matches(OAuth2Constants.LC_OAUTH_FOLDER_ID))).andReturn(folderId);
		// expect
		expect(mockConfig.getString(anyObject(String.class))).andReturn(null).atLeastOnce();
		expect(mockConfig.getString(anyObject(String.class), anyObject(String.class))).andReturn(null).atLeastOnce();

		PowerMock.replay(Configuration.class);
		replay(mockConfig);
		PowerMock.replay(LC.class);

		ClassManager.getHandler(client);

		PowerMock.verify(Configuration.class);
		verify(mockConfig);
		assertEquals(1, handlerCacheMap.size());
		assertNotNull(handlerCacheMap.get(client));
	}

	/**
	 * Test method for {@link ClassManager#getHandler}<br>
	 * Validates that a client handler is created and cached.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testGetHandlerBadClient() throws Exception {
		final String badClient = "not-a-client";
		expect(Configuration.buildConfiguration(matches(badClient)))
			.andThrow(new InvalidClientException("The specified client is unsupported."));

		PowerMock.replay(Configuration.class);

		try {
			ClassManager.getHandler(badClient);
		} catch (final Exception e) {
			PowerMock.verify(Configuration.class);
			assertEquals("The specified client is unsupported.", e.getMessage());
			return;
		}
		fail("Expected exception to be thrown for bad client name.");
	}
}
