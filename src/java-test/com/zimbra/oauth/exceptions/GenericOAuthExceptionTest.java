package com.zimbra.oauth.exceptions;

import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;

import java.util.Map;

import javax.ws.rs.core.Response.Status;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.oauth.models.ErrorObject;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Error;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * Test class for {@link GenericOAuthException}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ErrorObject.class, GenericOAuthException.class, OAuth2Utilities.class, ResponseObject.class})
public class GenericOAuthExceptionTest {

	/**
	 * Setup for tests.
	 *
	 * @throws Exception If there are issues mocking
	 */
	@Before
	public void setUp() throws Exception {
		PowerMock.mockStatic(OAuth2Utilities.class);
	}

	/**
	 * Test method for {@link GenericOAuthException#toResponse}<br>
	 * Validates that toResponse builds a response with error entity.
	 *
	 * @throws Exception If there are issues testing
	 */
	@Test
	public void testToResponse() throws Exception {
		final GenericOAuthException e = new GenericOAuthException();
		e.setStatus(Status.INTERNAL_SERVER_ERROR);
		e.setError(OAuth2Error.GENERIC_OAUTH_ERROR);
		final ErrorObject errorObject = new ErrorObject(e.getError(), e.getMessage());
		final ResponseObject<ErrorObject> entity = new ResponseObject<ErrorObject>(errorObject);

		// force use of fake entity
		PowerMock.expectNew(ErrorObject.class, e.getError(), e.getMessage()).andReturn(errorObject);
		PowerMock.expectNew(ResponseObject.class, errorObject).andReturn(entity);

		// expect the response builder call with fake entity + other params
		expect(OAuth2Utilities.buildResponse(eq(entity), eq(e.getStatus()), EasyMock.<Map<String, Object>> anyObject()))
			.andReturn(null);

		PowerMock.replay(ErrorObject.class);
		PowerMock.replay(ResponseObject.class);
		PowerMock.replay(OAuth2Utilities.class);

		e.toResponse(e);

		PowerMock.verify(ErrorObject.class);
		PowerMock.verify(ResponseObject.class);
		PowerMock.verify(OAuth2Utilities.class);
	}

}
