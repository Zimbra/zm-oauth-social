/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth Social Extension
 * Copyright (C) 2019 Synacor, Inc.
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
import com.zimbra.oauth.handlers.impl.SlackOAuth2Handler.SlackOAuth2Constants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * Test class for {@link SlackOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuth2DataSource.class, OAuth2Handler.class, SlackOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor("com.zimbra.client.ZMailbox")
public class SlackOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected SlackOAuth2Handler handler;

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
        handler = PowerMock.createPartialMockForAllMethodsExcept(SlackOAuth2Handler.class,
            "authorize", "authenticate", "buildScopeString");
        Whitebox.setInternalState(handler, "config", mockConfig);
        Whitebox.setInternalState(handler, "relayKey", SlackOAuth2Constants.RELAY_KEY.getValue());
        Whitebox.setInternalState(handler, "typeKey",
            OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue());
        Whitebox.setInternalState(handler, "authenticateUri",
            SlackOAuth2Constants.AUTHENTICATE_URI.getValue());
        Whitebox.setInternalState(handler, "authorizeUriTemplate",
            SlackOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue());
        Whitebox.setInternalState(handler, "client", SlackOAuth2Constants.CLIENT_NAME.getValue());
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
        Whitebox.setInternalState(handler, "requiredScopes", SlackOAuth2Constants.REQUIRED_SCOPES.getValue());
        Whitebox.setInternalState(handler, "scopeDelimiter", SlackOAuth2Constants.SCOPE_DELIMITER.getValue());
    }

    /**
     * Test method for {@link SlackOAuth2Handler#SlackOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testSlackOAuth2Handler() throws Exception {
        final OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

        PowerMock.mockStatic(OAuth2DataSource.class);
        expect(OAuth2DataSource.createDataSource(SlackOAuth2Constants.CLIENT_NAME.getValue(),
            SlackOAuth2Constants.HOST_SLACK.getValue())).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuth2DataSource.class);

        new SlackOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuth2DataSource.class);
    }

    /**
     * Test method for {@link SlackOAuth2Handler#authorize}<br>
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
            SlackOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(), clientId, encodedUri, "code",
            SlackOAuth2Constants.REQUIRED_SCOPES.getValue());
        // expect a contact state with no relay
        final String expectedAuthorize = authorizeBase + stateValue;

        // expect buildStateString call
        expect(handler.buildStateString("&", "", "noop", "")).andReturn(stateValue);

        // expect buildAuthorize call
        expect(handler.buildAuthorizeUri(SlackOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(),
            null, "noop")).andReturn(authorizeBase);

        replay(handler);

        final String authorizeLocation = handler.authorize(params, null);

        // verify build was called
        verify(handler);

        assertNotNull(authorizeLocation);
        assertEquals(expectedAuthorize, authorizeLocation);
    }

    /**
     * Test method for {@link SlackOAuth2Handler#authenticate}<br>
     * Validates that the authenticate method calls sync datasource.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticate() throws Exception {
        final String username = "test-user@localhost";
        final String accessToken = "access-token";
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
        expect(handler.getStorableToken(mockCredentials)).andReturn(accessToken);
        expect(handler.getPrimaryEmail(anyObject(JsonNode.class), anyObject(Account.class)))
            .andReturn(username);

        mockOAuthInfo.setTokenUrl(matches(SlackOAuth2Constants.AUTHENTICATE_URI.getValue()));
        EasyMock.expectLastCall().once();
        expect(mockOAuthInfo.getZmAuthToken()).andReturn(mockAuthToken);
        mockOAuthInfo.setUsername(username);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setRefreshToken(accessToken);
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
     * Test method for {@link SlackOAuth2Handler#buildScopeString}<br>
     * Validates that the buildScopeString method returns configured values
     * when no scopes are required, but some are configured in LDAP.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testBuildScopeString() throws Exception {
        // expect configured scope string
        final String expectedScopes = "chat:write:bot,chat:write:user,groups:write,bot,users:read,users:read.email,team:read";

        // expect to fetch the scopes from config
        expect(mockConfig.getString(anyObject(String.class), anyObject(String.class), anyObject(Account.class)))
            .andReturn(expectedScopes);

        replay(handler);
        replay(mockConfig);

        final String scopes = handler.buildScopeString(null, "noop");

        // verify build was called
        verify(handler);
        verify(mockConfig);

        assertEquals(expectedScopes, scopes);
    }

}
