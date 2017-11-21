package com.zimbra.oauth.resources;

import static org.easymock.EasyMock.expect;

import javax.ws.rs.core.Response;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

/**
 * Test class for {@link OAuth2Resource}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuth2ResourceUtilities.class})
public class OAuth2ResourceTest {

	/**
	 * Resource under test.
	 */
	protected OAuth2Resource resource = new OAuth2Resource();

	/**
	 * Setup for testing.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		PowerMock.mockStatic(OAuth2ResourceUtilities.class);
	}

	/**
	 * Test method for {@link OAuth2Resource#authorize}<br>
	 * Validates that the authorize method calls its utility method.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthorize() throws Exception {
		final String client = "yahoo";
		final String relay = null;
		final Response mockResponse = EasyMock.createMock(Response.class);

		expect(OAuth2ResourceUtilities.authorize(client, relay)).andReturn(mockResponse);

		PowerMock.replay(OAuth2ResourceUtilities.class);

		resource.authorize(client, relay);

		PowerMock.verify(OAuth2ResourceUtilities.class);
	}

	/**
	 * Test method for {@link OAuth2Resource#authenticate}<br>
	 * Validates that the authenticate method calls its utility method.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticate() throws Exception {
		final String client = "yahoo";
		final String code = "test-code";
		final String error = null;
		final String relay = null;
		final String zmAuthToken = "token-cookie";
		final Response mockResponse = EasyMock.createMock(Response.class);

		expect(OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken))
			.andReturn(mockResponse);

		PowerMock.replay(OAuth2ResourceUtilities.class);

		resource.authenticate(client, code, error, relay, zmAuthToken);

		PowerMock.verify(OAuth2ResourceUtilities.class);
	}

}
