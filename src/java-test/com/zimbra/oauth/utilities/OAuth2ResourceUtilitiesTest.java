package com.zimbra.oauth.utilities;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.util.Arrays;
import java.util.Map;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

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
		final String state = "test-relay";
		final String zmAuthToken = "test-zm-auth-token";
		final UriInfo mockUriInfo = EasyMock.createMock(UriInfo.class);
		final MultivaluedMap<String, String> params = new MultivaluedHashMap<String, String>(3);
		params.putSingle("code", code);
		params.putSingle("state", state);

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(mockUriInfo.getQueryParameters()).andReturn(params);
		expect(mockHandler.getAuthenticateParamKeys()).andReturn(Arrays.asList("code", "error", "state"));
		mockHandler.verifyAuthenticateParams(anyObject());
		EasyMock.expectLastCall();
		expect(mockHandler.authenticate(anyObject(OAuthInfo.class))).andReturn(true);
		expect(mockHandler.getRelay(anyObject())).andReturn(state);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		replay(mockUriInfo);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, mockUriInfo, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
		verify(mockUriInfo);
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
		final String state = "test-relay";
		final UriInfo mockUriInfo = EasyMock.createMock(UriInfo.class);
		final String zmAuthToken = "test-zm-auth-token";
		final MultivaluedMap<String, String> params = new MultivaluedHashMap<String, String>(3);
		params.putSingle("code", code);
		params.putSingle("error", error);
		params.putSingle("state", state);

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(mockUriInfo.getQueryParameters()).andReturn(params);
		expect(mockHandler.getAuthenticateParamKeys()).andReturn(Arrays.asList("code", "error", "state"));
		mockHandler.verifyAuthenticateParams(anyObject());
		EasyMock.expectLastCall().andThrow(new UserUnauthorizedException(error));
		expect(mockHandler.getRelay(anyObject())).andReturn(state);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		replay(mockUriInfo);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, mockUriInfo, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
		verify(mockUriInfo);
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
		final String state = "test-relay";
		final UriInfo mockUriInfo = EasyMock.createMock(UriInfo.class);
		final String zmAuthToken = "test-zm-auth-token";
		final MultivaluedMap<String, String> params = new MultivaluedHashMap<String, String>(3);
		params.putSingle("code", code);
		params.putSingle("error", error);
		params.putSingle("state", state);

		expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
		expect(mockUriInfo.getQueryParameters()).andReturn(params);
		expect(mockHandler.getAuthenticateParamKeys()).andReturn(Arrays.asList("code", "error", "state"));
		mockHandler.verifyAuthenticateParams(anyObject());
		EasyMock.expectLastCall();
		expect(mockHandler.getRelay(anyObject())).andReturn(state);
		expect(OAuth2Utilities.buildResponse(anyObject(), eq(Status.SEE_OTHER), EasyMock.<Map<String, Object>> anyObject())).andReturn(null);
		expect(mockHandler.authenticate(anyObject(OAuthInfo.class)))
			.andThrow(new UserUnauthorizedException("Access was denied during get_token!"));

		PowerMock.replay(ClassManager.class);
		replay(mockHandler);
		replay(mockUriInfo);
		PowerMock.replay(OAuth2Utilities.class);

		OAuth2ResourceUtilities.authenticate(client, mockUriInfo, zmAuthToken);

		PowerMock.verify(ClassManager.class);
		PowerMock.verify(OAuth2Utilities.class);
		verify(mockHandler);
		verify(mockUriInfo);
	}

}
