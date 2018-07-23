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
import com.zimbra.oauth.handlers.impl.OutlookOAuth2Handler.OutlookOAuth2Constants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * Test class for {@link OutlookOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuth2DataSource.class, OAuth2Handler.class, OutlookOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor("com.zimbra.client.ZMailbox")
public class OutlookOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected OutlookOAuth2Handler handler;

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
        handler = PowerMock.createPartialMockForAllMethodsExcept(OutlookOAuth2Handler.class,
            "authorize", "authenticate");
        Whitebox.setInternalState(handler, "config", mockConfig);
        Whitebox.setInternalState(handler, "relayKey", OutlookOAuth2Constants.RELAY_KEY.getValue());
        Whitebox.setInternalState(handler, "typeKey",
            OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue());
        Whitebox.setInternalState(handler, "authenticateUri",
            OutlookOAuth2Constants.AUTHENTICATE_URI.getValue());
        Whitebox.setInternalState(handler, "authorizeUriTemplate",
            OutlookOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue());
        Whitebox.setInternalState(handler, "requiredScopes",
            OutlookOAuth2Constants.REQUIRED_SCOPES.getValue());
        Whitebox.setInternalState(handler, "scopeDelimiter",
            OutlookOAuth2Constants.SCOPE_DELIMITER.getValue());
        Whitebox.setInternalState(handler, "client", OutlookOAuth2Constants.CLIENT_NAME.getValue());
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
    }

    /**
     * Test method for {@link OutlookOAuth2Handler#OutlookOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testOutlookOAuth2Handler() throws Exception {
        final OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

        PowerMock.mockStatic(OAuth2DataSource.class);
        expect(OAuth2DataSource.createDataSource(OutlookOAuth2Constants.CLIENT_NAME.getValue(),
            OutlookOAuth2Constants.HOST_OUTLOOK.getValue())).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuth2DataSource.class);

        new OutlookOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuth2DataSource.class);
    }

    /**
     * Test method for {@link OutlookOAuth2Handler#authorize}<br>
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
        params.put(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue(), "contact");
        final String authorizeBase = String.format(
            OutlookOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(), clientId, encodedUri, "code",
            OutlookOAuth2Constants.REQUIRED_SCOPES.getValue());
        // expect a contact state with no relay
        final String expectedAuthorize = authorizeBase + "&state=;contact";

        // expect buildAuthorize call
        expect(handler.buildAuthorizeUri(OutlookOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(),
            null, "contact")).andReturn(authorizeBase);

        replay(handler);

        final String authorizeLocation = handler.authorize(params, null);

        // verify build was called
        verify(handler);

        assertNotNull(authorizeLocation);
        assertEquals(expectedAuthorize, authorizeLocation);
    }

    /**
     * Test method for {@link OutlookOAuth2Handler#authenticate}<br>
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
        final JsonNode mockCredentialsRToken = EasyMock.createMock(JsonNode.class);

        PowerMock.mockStatic(OAuth2Handler.class);

        expect(mockOAuthInfo.getAccount()).andReturn(null);
        expect(mockConfig.getString(
            matches(String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue())),
            matches(OutlookOAuth2Constants.CLIENT_NAME.getValue()), anyObject())).andReturn(clientId);
        expect(mockConfig.getString(
            matches(String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue())),
            matches(OutlookOAuth2Constants.CLIENT_NAME.getValue()), anyObject())).andReturn(clientSecret);
        expect(mockConfig.getString(
            matches(String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(),
                OutlookOAuth2Constants.CLIENT_NAME.getValue())),
            matches(OutlookOAuth2Constants.CLIENT_NAME.getValue()), anyObject()))
                .andReturn(clientRedirectUri);
        expect(handler.getZimbraMailbox(anyObject(AuthToken.class), anyObject(Account.class)))
            .andReturn(mockZMailbox);
        expect(handler.getDatasourceCustomAttrs(anyObject())).andReturn(null);
        expect(OAuth2Handler.getTokenRequest(anyObject(OAuthInfo.class), anyObject(String.class)))
            .andReturn(mockCredentials);
        handler.validateTokenResponse(anyObject());
        EasyMock.expectLastCall().once();
        expect(mockCredentials.get("refresh_token")).andReturn(mockCredentialsRToken);
        expect(mockCredentialsRToken.asText()).andReturn(refreshToken);
        expect(handler.getPrimaryEmail(anyObject(JsonNode.class), anyObject(Account.class)))
            .andReturn(username);

        mockOAuthInfo.setClientId(matches(clientId));
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setClientSecret(matches(clientSecret));
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setClientRedirectUri(matches(clientRedirectUri));
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setTokenUrl(matches(OutlookOAuth2Constants.AUTHENTICATE_URI.getValue()));
        EasyMock.expectLastCall().once();
        expect(mockOAuthInfo.getZmAuthToken()).andReturn(mockAuthToken);
        mockOAuthInfo.setUsername(username);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setRefreshToken(refreshToken);
        EasyMock.expectLastCall().once();
        mockDataSource.syncDatasource(mockZMailbox, mockOAuthInfo, null);
        EasyMock.expectLastCall().once();

        replay(handler);
        PowerMock.replay(OAuth2Handler.class);
        replay(mockOAuthInfo);
        replay(mockConfig);
        replay(mockCredentials);
        replay(mockCredentialsRToken);
        replay(mockDataSource);

        handler.authenticate(mockOAuthInfo);

        verify(handler);
        PowerMock.verify(OAuth2Handler.class);
        verify(mockOAuthInfo);
        verify(mockConfig);
        verify(mockCredentials);
        verify(mockCredentialsRToken);
        verify(mockDataSource);
    }

}
