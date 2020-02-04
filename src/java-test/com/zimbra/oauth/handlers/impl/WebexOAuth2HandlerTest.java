/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2020 Synacor, Inc.
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
import java.util.HashMap;
import java.util.Map;

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
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.oauth.handlers.impl.WebexOAuth2Handler.WebexOAuth2Constants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2DataSource.DataSourceMetaData;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * Test class for {@link WebexOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSourceMetaData.class, OAuth2DataSource.class, WebexOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor({"com.zimbra.client.ZMailbox"})
public class WebexOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected WebexOAuth2Handler handler;

    /**
     * Mock configuration handler property.
     */
    protected Configuration mockConfig = EasyMock.createMock(Configuration.class);

    /**
     * Mock data source handler property.
     */
    protected OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

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
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        handler = setupHandler("authorize", "authenticate", "refresh", "buildScopeString");

        PowerMock.mockStatic(DataSourceMetaData.class);
    }

    protected WebexOAuth2Handler setupHandler(String... allowMethods) {
        final WebexOAuth2Handler handler = PowerMock.createPartialMockForAllMethodsExcept(WebexOAuth2Handler.class,
            allowMethods);
        Whitebox.setInternalState(handler, "config", mockConfig);
        Whitebox.setInternalState(handler, "relayKey", WebexOAuth2Constants.RELAY_KEY.getValue());
        Whitebox.setInternalState(handler, "typeKey",
            OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue());
        Whitebox.setInternalState(handler, "authenticateUri",
            WebexOAuth2Constants.AUTHENTICATE_URI.getValue());
        Whitebox.setInternalState(handler, "authorizeUriTemplate",
            WebexOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue());
        Whitebox.setInternalState(handler, "client", WebexOAuth2Constants.CLIENT_NAME.getValue());
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
        Whitebox.setInternalState(handler, "requiredScopes", WebexOAuth2Constants.REQUIRED_SCOPES.getValue());
        Whitebox.setInternalState(handler, "scopeDelimiter", WebexOAuth2Constants.SCOPE_DELIMITER.getValue());
        return handler;
    }

    /**
     * Test method for {@link WebexOAuth2Handler#WebexOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testWebexOAuth2Handler() throws Exception {
        final OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

        PowerMock.mockStatic(OAuth2DataSource.class);
        expect(OAuth2DataSource.createDataSource(WebexOAuth2Constants.CLIENT_NAME.getValue(),
            WebexOAuth2Constants.HOST_WEBEX.getValue())).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuth2DataSource.class);

        new WebexOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuth2DataSource.class);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#authorize}<br>
     * Validates that the authorize method returns a location with an encoded
     * redirect uri.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthorize() throws Exception {
        final String encodedUri = URLEncoder.encode(clientRedirectUri,
            OAuth2Constants.ENCODING.getValue());
        // use contact type
        final Map<String, String> params = new HashMap<String, String>();
        params.put(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue(), "noop");
        final String stateValue = "&state=%3Bnoop";
        final String authorizeBase = String.format(
            WebexOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(), clientId, encodedUri, "code",
            WebexOAuth2Constants.REQUIRED_SCOPES.getValue());
        // expect a contact state with no relay
        final String expectedAuthorize = authorizeBase + stateValue;

        // expect buildStateString call
        expect(handler.buildStateString("&", "", "noop", "")).andReturn(stateValue);

        // expect buildAuthorize call
        expect(handler.buildAuthorizeUri(WebexOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(),
            null, "noop")).andReturn(authorizeBase);

        replay(handler);

        final String authorizeLocation = handler.authorize(params, null);

        // verify build was called
        verify(handler);

        assertNotNull(authorizeLocation);
        assertEquals(expectedAuthorize, authorizeLocation);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#buildScopeString}<br>
     * Validates that the buildScopeString method returns an encoded scope string.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testBuildScopeString() throws Exception {
        final String scopeString = "spark:test_scope spark:another_test";

        // expect a % encoded scope string
        final String expectedScopes = "spark%3Apeople_read%20spark%3Atest_scope%20spark%3Aanother_test";

        expect(mockConfig.getString(anyObject(String.class), anyObject(String.class), anyObject(Account.class)))
            .andReturn(scopeString);

        replay(handler);
        replay(mockConfig);

        final String scopes = handler.buildScopeString(null, "noop");

        // verify build was called
        verify(handler);
        verify(mockConfig);

        assertNotNull(scopes);
        assertEquals(expectedScopes, scopes);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#buildScopeString}<br>
     * Validates that the buildScopeString method returns an encoded scope
     * string with empty string LDAP configured scopes.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testBuildScopeStringEmptyExtras() throws Exception {
        final String scopeString = "";

        // expect a % encoded scope string
        final String expectedScopes = "spark%3Apeople_read";

        expect(mockConfig.getString(anyObject(String.class), anyObject(String.class), anyObject(Account.class)))
            .andReturn(scopeString);

        replay(handler);
        replay(mockConfig);

        final String scopes = handler.buildScopeString(null, "noop");

        // verify build was called
        verify(handler);
        verify(mockConfig);

        assertNotNull(scopes);
        assertEquals(expectedScopes, scopes);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#buildScopeString}<br>
     * Validates that the buildScopeString method returns an encoded scope
     * string with null string LDAP configured scopes.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testBuildScopeStringNullExtras() throws Exception {
        final String scopeString = null;

        // expect a % encoded scope string
        final String expectedScopes = "spark%3Apeople_read";

        expect(mockConfig.getString(anyObject(String.class), anyObject(String.class), anyObject(Account.class)))
            .andReturn(scopeString);

        replay(handler);
        replay(mockConfig);

        final String scopes = handler.buildScopeString(null, "noop");

        // verify build was called
        verify(handler);
        verify(mockConfig);

        assertNotNull(scopes);
        assertEquals(expectedScopes, scopes);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#authenticate}<br>
     * Validates that the authenticate method calls sync datasource.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticate() throws Exception {
        final String username = "test-user@localhost";
        final String refreshToken = "refresh-token";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
        final ZMailbox mockZMailbox = EasyMock.createMock(ZMailbox.class);
        final JsonNode mockCredentials = EasyMock.createMock(JsonNode.class);
        final Map<String, Object> customAttrs = new HashMap<String, Object>();

        expect(mockOAuthInfo.getAccount()).andReturn(null);
        handler.loadClientConfig(null, mockOAuthInfo);
        EasyMock.expectLastCall();
        expect(mockOAuthInfo.getClientId()).andReturn(clientId);
        expect(mockOAuthInfo.getClientSecret()).andReturn(clientSecret);
        expect(handler.getDatasourceCustomAttrs(anyObject())).andReturn(customAttrs);
        expect(handler.getZimbraMailbox(anyObject(AuthToken.class), anyObject(Account.class)))
            .andReturn(mockZMailbox);
        expect(handler.getToken(anyObject(OAuthInfo.class), anyObject(String.class)))
            .andReturn(mockCredentials);
        handler.validateTokenResponse(anyObject());
        EasyMock.expectLastCall().once();
        expect(handler.getStorableToken(mockCredentials)).andReturn(refreshToken);
        expect(handler.getPrimaryEmail(anyObject(JsonNode.class), anyObject(Account.class)))
            .andReturn(username);

        mockOAuthInfo.setTokenUrl(matches(WebexOAuth2Constants.AUTHENTICATE_URI.getValue()));
        EasyMock.expectLastCall().once();
        expect(mockOAuthInfo.getZmAuthToken()).andReturn(mockAuthToken);
        mockOAuthInfo.setUsername(username);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setRefreshToken(refreshToken);
        EasyMock.expectLastCall().once();
        mockDataSource.syncDatasource(mockZMailbox, mockOAuthInfo, customAttrs);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setClientSecret(null);
        EasyMock.expectLastCall().once();
        handler.setResponseParams(mockCredentials, mockOAuthInfo);
        EasyMock.expectLastCall().once();

        replay(handler);
        replay(mockOAuthInfo);
        replay(mockConfig);
        replay(mockCredentials);
        replay(mockDataSource);

        handler.authenticate(mockOAuthInfo);

        verify(handler);
        verify(mockOAuthInfo);
        verify(mockConfig);
        verify(mockCredentials);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link WebexOAuth2Handler#refresh}<br>
     * Validates that the refresh method calls sync datasource.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testRefresh() throws Exception {
        final String username = "test-user@localhost";
        final String accessToken = "access-token";
        final String refreshToken = "refresh-token";
        final String type = "noop";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
        final ZMailbox mockZMailbox = EasyMock.createMock(ZMailbox.class);
        final JsonNode mockCredentials = EasyMock.createMock(JsonNode.class);
        final Map<String, Object> customAttrs = new HashMap<String, Object>();

        expect(mockOAuthInfo.getAccount()).andReturn(null);
        handler.loadClientConfig(null, mockOAuthInfo);
        EasyMock.expectLastCall();
        expect(mockOAuthInfo.getClientId()).andReturn(clientId);
        expect(mockOAuthInfo.getClientSecret()).andReturn(clientSecret);
        expect(mockOAuthInfo.getUsername()).andReturn(username);
        expect(mockOAuthInfo.getParam(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue())).andReturn(type);
        expect(mockDataSource.getRefreshToken(mockZMailbox, username, type)).andReturn(refreshToken);
        expect(handler.getDatasourceCustomAttrs(anyObject())).andReturn(customAttrs);
        expect(handler.getZimbraMailbox(anyObject(AuthToken.class), anyObject(Account.class)))
            .andReturn(mockZMailbox);
        expect(handler.getToken(anyObject(OAuthInfo.class), anyObject(String.class)))
            .andReturn(mockCredentials);
        handler.validateRefreshTokenResponse(anyObject());
        EasyMock.expectLastCall().once();
        expect(handler.getStorableToken(mockCredentials)).andReturn(refreshToken);

        mockOAuthInfo.setTokenUrl(matches(WebexOAuth2Constants.AUTHENTICATE_URI.getValue()));
        EasyMock.expectLastCall().once();
        expect(mockOAuthInfo.getZmAuthToken()).andReturn(mockAuthToken);
        expect(mockOAuthInfo.getRefreshToken()).andReturn(null);
        mockOAuthInfo.setRefreshToken(refreshToken);
        EasyMock.expectLastCall().times(2);
        // expect to get a useable token and set it
        expect(handler.getUsableToken(mockCredentials)).andReturn(accessToken);
        mockOAuthInfo.setAccessToken(accessToken);
        EasyMock.expectLastCall().once();
        expect(handler.isStorableTokenRefreshed(refreshToken, mockCredentials)).andReturn(true);
        mockDataSource.syncDatasource(mockZMailbox, mockOAuthInfo, customAttrs);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setClientSecret(null);
        EasyMock.expectLastCall().once();
        handler.setResponseParams(mockCredentials, mockOAuthInfo);
        EasyMock.expectLastCall().once();

        replay(handler);
        replay(mockOAuthInfo);
        replay(mockConfig);
        replay(mockCredentials);
        replay(mockDataSource);

        handler.refresh(mockOAuthInfo);

        verify(handler);
        verify(mockOAuthInfo);
        verify(mockConfig);
        verify(mockCredentials);
        verify(mockDataSource);
    }

}
