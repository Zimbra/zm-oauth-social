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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.common.service.ServiceException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.managers.ClassManager;
import com.zimbra.oauth.models.OAuthInfo;

/**
 * Test class for {@link OAuth2ResourceUtilities}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ ClassManager.class, OAuth2Utilities.class })
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
     * Validates that authorize retrieves a location and responds with a
     * Status.SEE_OTHER response.
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

        PowerMock.replay(ClassManager.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authorize(client, relay);

        PowerMock.verify(ClassManager.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate triggers the handler authenticate and
     * responds with a Status.SEE_OTHER response.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticate() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String state = "test-relay";
        final String zmAuthToken = "test-zm-auth-token";
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAuthenticateParams(anyObject());
        EasyMock.expectLastCall();
        expect(mockHandler.authenticate(anyObject(OAuthInfo.class))).andReturn(true);
        expect(mockHandler.getRelay(anyObject())).andReturn(state);

        PowerMock.replay(ClassManager.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, params, zmAuthToken);

        PowerMock.verify(ClassManager.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate with error param responds with a
     * Status.SEE_OTHER response.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticateWithAuthorizeError() throws Exception {
        final String client = "test-client";
        final String code = "test-code";
        final String error = "access_denied";
        final String state = "test-relay";
        final String zmAuthToken = "test-zm-auth-token";
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("error", new String[] { error });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAuthenticateParams(anyObject());
        EasyMock.expectLastCall().andThrow(ServiceException.PERM_DENIED(error));
        expect(mockHandler.getRelay(anyObject())).andReturn(state);

        PowerMock.replay(ClassManager.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, params, zmAuthToken);

        PowerMock.verify(ClassManager.class);
        verify(mockHandler);
    }

    /**
     * Test method for {@link OAuth2ResourceUtilities#authenticate}<br>
     * Validates that authenticate responds with a Status.SEE_OTHER response
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
        final String zmAuthToken = "test-zm-auth-token";
        final Map<String, String[]> params = new HashMap<String, String[]>(3);
        params.put("code", new String[] { code });
        params.put("error", new String[] { error });
        params.put("state", new String[] { state });

        expect(ClassManager.getHandler(matches(client))).andReturn(mockHandler);
        expect(mockHandler.getAuthenticateParamKeys())
            .andReturn(Arrays.asList("code", "error", "state"));
        mockHandler.verifyAuthenticateParams(anyObject());
        EasyMock.expectLastCall();
        expect(mockHandler.getRelay(anyObject())).andReturn(state);
        expect(mockHandler.authenticate(anyObject(OAuthInfo.class)))
            .andThrow(ServiceException.PERM_DENIED("Access was denied during get_token!"));

        PowerMock.replay(ClassManager.class);
        replay(mockHandler);

        OAuth2ResourceUtilities.authenticate(client, params, zmAuthToken);

        PowerMock.verify(ClassManager.class);
        verify(mockHandler);
    }

}
