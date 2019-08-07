/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2018 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.oauth.utilities;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.ws.rs.core.Response.Status;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.managers.ClassManager;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.models.ResponseObject;

/**
 * Test class for {@link OAuth2ResourceUtilities}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ ClassManager.class, OAuth2ResourceUtilities.class, OAuth2Utilities.class })
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
        PowerMock.mockStaticPartial(OAuth2ResourceUtilities.class, "getAccount", "getAuthToken",
            "isJWT");
        PowerMock.mockStatic(OAuth2Utilities.class);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authorize}<br>
     * Validates that authorize retrieves a location and responds with a
     * location string.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthorize() throws Exception {
        final String client = "test-client";
        final String relay = "test-relay";
        final String location = "result-location";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);

        // expect the handler to be fetched
        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        // expect the auth token to be fetched
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject());
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        // expect isJWT to be called
        OAuth2ResourceUtilities.isJWT(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(false);
        // expect the client's required params to be fetched
        expect(mockHandler.getAuthorizeParamKeys()).andReturn(Arrays.asList("relay", "type"));
        // expect to verify the present params
        mockHandler.verifyAuthorizeParams(anyObject());
        EasyMock.expectLastCall();
        // expect to have the handler authorize using a relay param
        final Map<String, String> params = new HashMap<String, String>();
        params.put("relay", relay);
        expect(mockHandler.authorize(params, null)).andReturn(location);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        // pass in multi-valued params and expect them to be parsed
        final Map<String, String[]> rawParams = new HashMap<String, String[]>();
        final String[] multiRelay = { relay };
        rawParams.put("relay", multiRelay);
        OAuth2ResourceUtilities.authorize(client, new Cookie[] {}, new HashMap<String, String>(),
            rawParams);

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authorize}<br>
     * Validates that authorize passes along a given JWT to the handler.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthorizeWithJWT() throws Exception {
        final String client = "test-client";
        final String relay = "test-relay";
        final String location = "result-location";
        final String jwt = "test-jwt";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);

        // expect the handler to be fetched
        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        // expect the auth token to be fetched
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject());
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        // expect isJWT to be called
        OAuth2ResourceUtilities.isJWT(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(true);
        // expect the encoded jwt to be fetched
        expect(mockAuthToken.getEncoded()).andReturn(jwt);
        // expect the client's required params to be fetched
        expect(mockHandler.getAuthorizeParamKeys()).andReturn(Arrays.asList("relay", "type"));
        // expect to verify the present params
        mockHandler.verifyAuthorizeParams(anyObject());
        EasyMock.expectLastCall();
        // expect to have the handler authorize using a relay param
        final Map<String, String> params = new HashMap<String, String>();
        params.put(OAuth2HttpConstants.JWT_PARAM_KEY.getValue(), jwt);
        params.put("relay", relay);
        expect(mockHandler.authorize(params, null)).andReturn(location);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);
        replay(mockAuthToken);

        // pass in multi-valued params and expect them to be parsed
        final Map<String, String[]> rawParams = new HashMap<String, String[]>();
        final String[] multiRelay = { relay };
        rawParams.put("relay", multiRelay);
        OAuth2ResourceUtilities.authorize(client, new Cookie[] {}, new HashMap<String, String>(),
            rawParams);

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
        verify(mockAuthToken);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate triggers the handler authenticate and
     * responds with a location string.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticate() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String state = "test-relay";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), anyObject(String.class));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAndSplitAuthenticateParams(anyObject());
        EasyMock.expectLastCall();
        expect(mockHandler.authenticate(anyObject(OAuthInfo.class))).andReturn(true);
        expect(mockHandler.getRelay(anyObject())).andReturn(state);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, new Cookie[] {}, new HashMap<String, String>(),
            params);

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate uses the JWT from the relay.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticateWithJWT() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String state = "test-relay";
        final String jwt = "test-jwt";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final Map<String, String> params = new HashMap<String, String>(3);
        params.put("code", code);
        params.put("state", state);
        params.put(OAuth2HttpConstants.JWT_PARAM_KEY.getValue(), jwt);

        PowerMock.mockStaticPartial(OAuth2ResourceUtilities.class, "getAccount", "getAuthToken",
            "isJWT", "getParams");

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        OAuth2ResourceUtilities.getParams(anyObject(), anyObject());
        PowerMock.expectLastCall().andReturn(params);
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), matches(jwt));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAndSplitAuthenticateParams(anyObject());
        EasyMock.expectLastCall();
        expect(mockHandler.authenticate(anyObject(OAuthInfo.class))).andReturn(true);
        expect(mockHandler.getRelay(anyObject())).andReturn(state);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, new Cookie[] {}, new HashMap<String, String>(),
            new HashMap<String, String[]>());

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate with error param responds with a
     * location string.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticateWithAuthorizeError() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String error = "access_denied";
        final String state = "test-relay";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("error", new String[] { error });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), anyObject(String.class));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAndSplitAuthenticateParams(anyObject());
        EasyMock.expectLastCall().andThrow(ServiceException.PERM_DENIED(error));
        expect(mockHandler.getRelay(anyObject())).andReturn(state);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, new Cookie[] {}, new HashMap<String, String>(),
            params);

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate responds with a location string response
     * when a ServiceException is thrown during authentication.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticateUserUnauthorizedException() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String error = null;
        final String state = "test-relay";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("error", new String[] { error });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), anyObject(String.class));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAndSplitAuthenticateParams(anyObject());
        EasyMock.expectLastCall();
        expect(mockHandler.getRelay(anyObject())).andReturn(state);
        expect(mockHandler.authenticate(anyObject(OAuthInfo.class)))
            .andThrow(ServiceException.PERM_DENIED("Access was denied during get_token!"));

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, new Cookie[] {}, new HashMap<String, String>(),
            params);

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#refresh}<br>
     * Validates that refresh triggers the handler refresh and
     * responds with a ResponseObject.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testRefresh() throws Exception {
        final String client = "test-client";
        final String identifier = "test@zmc.com";
        final String type = "noop";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final Map<String, String[]> params = new HashMap<String, String[]>(1);
        params.put("type", new String[] { type });

        PowerMock.mockStaticPartial(OAuth2ResourceUtilities.class, "getAccount", "getAuthToken");

        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), anyObject(String.class));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        expect(mockHandler.getAuthorizeParamKeys())
            .andReturn(Arrays.asList("state", "type"));
        expect(mockHandler.refresh(anyObject(OAuthInfo.class))).andReturn(true);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        final ResponseObject<?> response = OAuth2ResourceUtilities.refresh(client, identifier,
            new Cookie[] {}, new HashMap<String, String>(), params);
        assertNotNull(response);
        assertEquals(Status.OK.getStatusCode(), response.get_meta().getStatus());

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }


    /**
     * Test method for {@link OAuth2ResourceUtilities#info}<br>
     * Validates that info triggers the handler info and
     * responds with a ResponseObject.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testInfo() throws Exception {
        final String client = "test-client";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);

        PowerMock.mockStaticPartial(OAuth2ResourceUtilities.class, "getAccount", "getAuthToken");

        OAuth2ResourceUtilities.getAuthToken(anyObject(), anyObject(), anyObject(String.class));
        PowerMock.expectLastCall().andReturn(mockAuthToken);
        // expect the account to be fetched
        OAuth2ResourceUtilities.getAccount(anyObject(AuthToken.class));
        PowerMock.expectLastCall().andReturn(null);
        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        expect(mockHandler.info(anyObject(OAuthInfo.class))).andReturn(true);

        PowerMock.replay(ClassManager.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        replay(mockHandler);

        final ResponseObject<?> response = OAuth2ResourceUtilities.info(client, new Cookie[] {},
            new HashMap<String, String>());
        assertNotNull(response);
        assertEquals(Status.OK.getStatusCode(), response.get_meta().getStatus());

        PowerMock.verify(ClassManager.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        verify(mockHandler);
    }

}
