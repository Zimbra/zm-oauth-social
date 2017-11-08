package com.zimbra.oauth.utilities;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyMapOf;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.matches;
import static org.mockito.Matchers.refEq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import javax.ws.rs.core.Response.Status;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
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
@PrepareForTest({ClassManager.class, OAuth2ResourceUtilities.class, OAuth2Utilities.class})
public class OAuth2ResourceUtilitiesTest {

	/**
	 * Mock handler.
	 */
	protected IOAuth2Handler mockHandler = PowerMockito.mock(IOAuth2Handler.class);

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		PowerMockito.mockStatic(ClassManager.class);
		PowerMockito.mockStatic(OAuth2ResourceUtilities.class);
		PowerMockito.mockStatic(OAuth2Utilities.class);
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

		PowerMockito.when(OAuth2ResourceUtilities.authorize(anyString(), anyString())).thenCallRealMethod();
		PowerMockito.when(ClassManager.getHandler(anyString())).thenReturn(mockHandler);

		OAuth2ResourceUtilities.authorize(client, relay);

		PowerMockito.verifyStatic();
		ClassManager.getHandler(matches(client));
		verify(mockHandler).authorize(matches(relay));
		PowerMockito.verifyStatic();
		OAuth2Utilities.buildResponse(any(), refEq(Status.SEE_OTHER), anyMapOf(String.class, Object.class));
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

		PowerMockito
			.when(OAuth2ResourceUtilities.authenticate(anyString(), anyString(), anyString(), anyString(), anyString()))
			.thenCallRealMethod();
		PowerMockito.when(ClassManager.getHandler(anyString())).thenReturn(mockHandler);

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMockito.verifyStatic();
		ClassManager.getHandler(matches(client));
		verify(mockHandler).authenticate(any(OAuthInfo.class));
		PowerMockito.verifyStatic();
		OAuth2Utilities.buildResponse(any(), refEq(Status.SEE_OTHER), anyMapOf(String.class, Object.class));
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

		PowerMockito
			.when(OAuth2ResourceUtilities.authenticate(anyString(), anyString(), anyString(), anyString(), anyString()))
			.thenCallRealMethod();
		PowerMockito.when(ClassManager.getHandler(anyString())).thenReturn(mockHandler);

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMockito.verifyStatic();
		ClassManager.getHandler(matches(client));
		verify(mockHandler, never()).authenticate(any());
		PowerMockito.verifyStatic();
		OAuth2Utilities.buildResponse(any(), refEq(Status.SEE_OTHER), anyMapOf(String.class, Object.class));
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

		PowerMockito
			.when(OAuth2ResourceUtilities.authenticate(anyString(), anyString(), anyString(), anyString(), anyString()))
			.thenCallRealMethod();
		PowerMockito.when(ClassManager.getHandler(anyString())).thenReturn(mockHandler);
		PowerMockito.when(mockHandler.authenticate(any(OAuthInfo.class)))
			.thenThrow(new UserUnauthorizedException("Access was denied during get_token!"));

		OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);

		PowerMockito.verifyStatic();
		ClassManager.getHandler(matches(client));
		verify(mockHandler).authenticate(any(OAuthInfo.class));
		PowerMockito.verifyStatic();
		OAuth2Utilities.buildResponse(any(), refEq(Status.SEE_OTHER), anyMapOf(String.class, Object.class));
	}

}
