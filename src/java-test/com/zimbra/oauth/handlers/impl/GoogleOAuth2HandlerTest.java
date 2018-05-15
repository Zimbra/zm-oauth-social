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
package com.zimbra.oauth.handlers.impl;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URLEncoder;

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
import com.zimbra.oauth.handlers.impl.GoogleOAuth2Handler.GoogleConstants;
import com.zimbra.oauth.models.OAuthDataSource;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * Test class for {@link GoogleOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuthDataSource.class, GoogleOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor("com.zimbra.client.ZMailbox")
public class GoogleOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected GoogleOAuth2Handler handler;

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
     * Hostname for testing.
     */
    protected final String hostname = "localhost";

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
        handler = PowerMock.createPartialMockForAllMethodsExcept(GoogleOAuth2Handler.class,
            "authorize", "authenticate", "buildAuthorizeUri");
        Whitebox.setInternalState(handler, "relayKey", GoogleConstants.RELAY_KEY);
        Whitebox.setInternalState(handler, "clientRedirectUri", clientRedirectUri);
        Whitebox.setInternalState(handler, "clientId", clientId);
        Whitebox.setInternalState(handler, "clientSecret", clientSecret);
        Whitebox.setInternalState(handler, "scope", GoogleConstants.REQUIRED_SCOPES);
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
        Whitebox.setInternalState(handler, "authorizeUri", handler.buildAuthorizeUri(GoogleConstants.AUTHORIZE_URI_TEMPLATE));
    }

    /**
     * Test method for {@link GoogleOAuth2Handler#GoogleOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testGoogleOAuth2Handler() throws Exception {
        final OAuthDataSource mockDataSource = EasyMock.createMock(OAuthDataSource.class);

        expect(mockConfig.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE,
            OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE))
                .andReturn(OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE);
        expect(mockConfig.getString(OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME)).andReturn(hostname);
        expect(mockConfig.getString(String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, GoogleConstants.CLIENT_NAME))).andReturn(clientId);
        expect(mockConfig.getString(String.format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, GoogleConstants.CLIENT_NAME))).andReturn(clientSecret);
        expect(mockConfig.getString(String.format(OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, GoogleConstants.CLIENT_NAME))).andReturn(clientRedirectUri);
        expect(mockConfig.getString(String.format(OAuth2Constants.LC_OAUTH_SCOPE_TEMPLATE, GoogleConstants.CLIENT_NAME))).andReturn(null);
        PowerMock.mockStatic(OAuthDataSource.class);
        expect(OAuthDataSource.createDataSource(GoogleConstants.CLIENT_NAME,
            GoogleConstants.HOST_GOOGLE)).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuthDataSource.class);

        new GoogleOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuthDataSource.class);
    }

    /**
     * Test method for {@link GoogleOAuth2Handler#authorize}<br>
     * Validates that the authorize method returns a location with an encoded
     * redirect uri.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthorize() throws Exception {
        final String encodedUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);

        final String authorizeLocation = handler.authorize(null);

        assertNotNull(authorizeLocation);
        assertEquals(String.format(GoogleConstants.AUTHORIZE_URI_TEMPLATE, clientId, encodedUri,
            "code", GoogleConstants.REQUIRED_SCOPES), authorizeLocation);
    }

    /**
     * Test method for {@link GoogleOAuth2Handler#authenticate}<br>
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
        expect(handler.authenticateRequest(anyObject(OAuthInfo.class), matches(clientRedirectUri)))
            .andReturn(mockCredentials);
        expect(mockCredentials.get("refresh_token")).andReturn(mockCredentialsRToken);
        expect(mockCredentialsRToken.asText()).andReturn(refreshToken);
        expect(handler.getPrimaryEmail(anyObject(JsonNode.class))).andReturn(username);

        expect(mockOAuthInfo.getZmAuthToken()).andReturn(zmAuthToken);
        mockOAuthInfo.setUsername(username);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setRefreshToken(refreshToken);
        EasyMock.expectLastCall().once();
        mockDataSource.updateCredentials(mockZMailbox, mockOAuthInfo);
        EasyMock.expectLastCall().once();

        replay(handler);
        replay(mockOAuthInfo);
        replay(mockCredentials);
        replay(mockCredentialsRToken);
        replay(mockDataSource);

        handler.authenticate(mockOAuthInfo);

        verify(handler);
        verify(mockOAuthInfo);
        verify(mockCredentials);
        verify(mockCredentialsRToken);
        verify(mockDataSource);
    }

}
