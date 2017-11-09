package com.zimbra.oauth.utilities;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.util.Map;

import javax.ws.rs.core.Response.Status;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.managers.ClassManager;
import com.zimbra.oauth.models.OAuthInfo;

/**
 * Test class for {@link OAuth2ResourceUtilities}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ClassManager.class, OAuth2Utilities.class})
public class OAuth2ResourceUtilitiesTest {

	/**
	 * Mock handler.
	 */
	protected IOAuth2Handler mockHandler = EasyMock.createMock(IOAuth2Handler.class);

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		PowerMock.mockStatic(ClassManager.class);
		PowerMock.mockStatic(OAuth2Utilities.class);
	}

	/**
	 * Test method for {@link OAuth2ResourceUtilities#authorize}<br>
	 * Validates that authorize retrieves a location and responds with a Status.SEE_OTHER response.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthorize() throws Exception {
		final String client = "test-client";
		final String relay = "test-relay";
		final String location = "result-location";

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(mockHandler.authorize(matches(relay))).andReturn(location);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authorize(client, relay);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
	}

	/**
	 * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
	 * Validates that authenticate triggers the handler authenticate and responds with a Status.SEE_OTHER response.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticate() throws Exception {
		final String client = "test-client";
		final String code = "test-code";
		final String error = null;
		final String relay = "test-relay";
		final String zmAuthToken = "test-zm-auth-token";

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(mockHandler.authenticate(anyObject(OAuthInfo.class))).andReturn(true);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
	}

	/**
	 * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
	 * Validates that authenticate with error param responds with a Status.SEE_OTHER response.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticateWithAuthorizeError() throws Exception {
		final String client = "test-client";
		final String code = "test-code";
		final String error = "access_denied";
		final String relay = "test-relay";
		final String zmAuthToken = "test-zm-auth-token";

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
	}

	/**
	 * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
	 * Validates that authenticate responds with a Status.SEE_OTHER response
	 * when a UserUnauthorizedException is thrown during authentication.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testAuthenticateUserUnauthorizedException() throws Exception {
		final String client = "test-client";
		final String code = "test-code";
		final String error = null;
		final String relay = "test-relay";
		final String zmAuthToken = "test-zm-auth-token";

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);
		expect(mockHandler.authenticate(anyObject(OAuthInfo.class)))
			.andThrow(new UserUnauthorizedException("Access was denied during get_token!"));

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
	}

}
