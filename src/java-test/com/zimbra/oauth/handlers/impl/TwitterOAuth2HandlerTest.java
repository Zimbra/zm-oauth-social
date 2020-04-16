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

import java.util.HashMap;
import java.util.Map;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.zimbra.client.ZMailbox;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterOAuth2Constants;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;

/**
 * Test class for {@link TwitterOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuth2DataSource.class, OAuth2Handler.class, TwitterOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor("com.zimbra.client.ZMailbox")
@PowerMockIgnore({"javax.crypto.*" })
public class TwitterOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected TwitterOAuth2Handler handler;

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
        handler = PowerMock.createPartialMockForAllMethodsExcept(TwitterOAuth2Handler.class,
            "authorize", "authenticate", "splitToMap");
        Whitebox.setInternalState(handler, "config", mockConfig);
        Whitebox.setInternalState(handler, "relayKey", TwitterOAuth2Constants.RELAY_KEY.getValue());
        Whitebox.setInternalState(handler, "typeKey",
            OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue());
        Whitebox.setInternalState(handler, "authenticateUri",
            TwitterOAuth2Constants.AUTHENTICATE_URI.getValue());
        Whitebox.setInternalState(handler, "authorizeUriTemplate",
            TwitterOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue());
        Whitebox.setInternalState(handler, "client", TwitterOAuth2Constants.CLIENT_NAME.getValue());
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
    }

    /**
     * Test method for {@link TwitterOAuth2Handler#TwitterOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testTwitterOAuth2Handler() throws Exception {
        final OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

        PowerMock.mockStatic(OAuth2DataSource.class);
        expect(OAuth2DataSource.createDataSource(TwitterOAuth2Constants.CLIENT_NAME.getValue(),
            TwitterOAuth2Constants.HOST_TWITTER.getValue())).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuth2DataSource.class);

        new TwitterOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuth2DataSource.class);
    }

    /**
     * Test method for {@link TwitterOAuth2Handler#authorize}<br>
     * Validates that the authorize method returns a location with an encoded
     * redirect uri.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthorize() throws Exception {
        final String authorizeToken = "token";
        final String authorizeSecret = "secret";
        final String authorizeTokenRaw = "oauth_token=%s&oauth_token_secret=%s&oauth_callback_confirmed=%s";
        final String stateValue = "?state=%3Bcontact";
        // use contact type
        final Map<String, String> params = new HashMap<String, String>();
        params.put(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue(), "contact");
        // expect a redirect with just a token
        final String expectedAuthorize = String.format(
            TwitterOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(), authorizeToken);

        // expect buildStateString call
        expect(handler.buildStateString("?", "", "contact", "")).andReturn(stateValue);

        // expect authorizeRequest call
        expect(handler.authorizeRequest(null, stateValue))
            .andReturn(String.format(authorizeTokenRaw, authorizeToken, authorizeSecret, true));

        replay(handler);

        final String authorizeLocation = handler.authorize(params, null);

        // verify build was called
        verify(handler);

        assertNotNull(authorizeLocation);
        assertEquals(expectedAuthorize, authorizeLocation);
    }

    /**
     * Test method for {@link TwitterOAuth2Handler#authenticate}<br>
     * Validates that the authenticate method calls sync datasource.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testAuthenticate() throws Exception {
        final String username = "test-user";
        final String authToken = "auth-token";
        final String tokenSecret = "auth-secret";
        final AuthToken mockAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
        final ZMailbox mockZMailbox = EasyMock.createMock(ZMailbox.class);
        final Map<String, String> credentials = new HashMap<String, String>(3);
        credentials.put("oauth_token", authToken);
        credentials.put("oauth_token_secret", tokenSecret);
        credentials.put("screen_name", username);

        PowerMock.mockStatic(OAuth2Handler.class);

        expect(mockOAuthInfo.getAccount()).andReturn(null);
        handler.loadClientConfig(null, mockOAuthInfo);
        EasyMock.expectLastCall();
        expect(mockOAuthInfo.getClientId()).andReturn(clientId);
        expect(mockOAuthInfo.getClientSecret()).andReturn(clientSecret);
        expect(mockOAuthInfo.getParam("oauth_token")).andReturn("authorize-token");
        expect(handler.getZimbraMailbox(anyObject(AuthToken.class), anyObject(Account.class)))
            .andReturn(mockZMailbox);
        expect(handler.getDatasourceCustomAttrs(anyObject())).andReturn(null);
        expect(handler.getTokenRequestMap(anyObject(OAuthInfo.class), anyObject(String.class)))
            .andReturn(credentials);

        mockOAuthInfo.setTokenUrl(matches(TwitterOAuth2Constants.AUTHENTICATE_URI.getValue()));
        EasyMock.expectLastCall().once();
        expect(mockOAuthInfo.getZmAuthToken()).andReturn(mockAuthToken);
        mockOAuthInfo.setUsername(username);
        EasyMock.expectLastCall().once();
        mockOAuthInfo.setRefreshToken(authToken + TwitterOAuth2Constants.TOKEN_DELIMITER.getValue() + tokenSecret);
        EasyMock.expectLastCall().once();
        mockDataSource.syncDatasource(mockZMailbox, mockOAuthInfo, null);
        EasyMock.expectLastCall().once();

        replay(handler);
        PowerMock.replay(OAuth2Handler.class);
        replay(mockOAuthInfo);
        replay(mockConfig);
        replay(mockDataSource);

        handler.authenticate(mockOAuthInfo);

        verify(handler);
        PowerMock.verify(OAuth2Handler.class);
        verify(mockOAuthInfo);
        verify(mockConfig);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link TwitterOAuth2Handler#splitToMap}<br>
     * Validates that the splitToMap method splits a tokenized string.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testSplitToMap() throws Exception {
        final String tokenizedStringTemplate = "oauth_token=%s&oauth_token_secret=%s&oauth_callback_confirmed=%s";

        final Map<String, String> res = handler.splitToMap(
            String.format(tokenizedStringTemplate, "token", "secret", "true"));

        assertNotNull(res);
        assertEquals("token", res.get("oauth_token"));
        assertEquals("secret", res.get("oauth_token_secret"));
        assertEquals("true", res.get("oauth_callback_confirmed"));
    }

    /**
     * Test method for {@link TwitterOAuth2Handler#splitToMap}<br>
     * Validates that the splitToMap method handles null input,
     * empty values, and broken input.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testSplitToMapBadInput() throws Exception {
        // null test
        final Map<String, String> nullTestRes = handler.splitToMap(null);
        assertNotNull(nullTestRes);
        assertEquals(0, nullTestRes.size());

        // empty value test
        final Map<String, String> emptyTestRes = handler.splitToMap("emptyx=");
        assertNotNull(emptyTestRes);
        assertEquals(1, emptyTestRes.size());
        assertEquals("", emptyTestRes.get("emptyx"));

        // broken token test
        final Map<String, String> brokenTestRes = handler.splitToMap("emptyx=&baddata&zerome=true");
        assertNotNull(brokenTestRes);
        assertEquals(2, brokenTestRes.size());
        assertEquals("", brokenTestRes.get("emptyx"));
        assertEquals("true", brokenTestRes.get("zerome"));

    }

}
