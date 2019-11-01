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
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.HttpMethod;

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
import com.google.common.collect.ImmutableMap;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.oauth.handlers.impl.ZoomOAuth2Handler.ZoomOAuth2Constants;
import com.zimbra.oauth.models.GuestRequest;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2CacheUtilities;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2DataSource.DataSourceMetaData;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ProxyUtilities;

/**
 * Test class for {@link ZoomOAuth2Handler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSourceMetaData.class, OAuth2DataSource.class, OAuth2ProxyUtilities.class, ZoomOAuth2Handler.class, ZMailbox.class })
@SuppressStaticInitializationFor({"com.zimbra.client.ZMailbox", "com.zimbra.oauth.utilities.OAuth2CacheUtilities"})
public class ZoomOAuth2HandlerTest {

    /**
     * Class under test.
     */
    protected ZoomOAuth2Handler handler;

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
        handler = setupHandler("authorize", "authenticate", "refresh", "event", "deauthorize", "headers",
            "findStoredAccessToken", "findAndCacheStoredRefreshableAccessToken");

        PowerMock.mockStatic(OAuth2CacheUtilities.class);
        PowerMock.mockStatic(OAuth2ProxyUtilities.class);
        PowerMock.mockStatic(DataSourceMetaData.class);
    }

    protected ZoomOAuth2Handler setupHandler(String... allowMethods) {
        final ZoomOAuth2Handler handler = PowerMock.createPartialMockForAllMethodsExcept(ZoomOAuth2Handler.class,
            allowMethods);
        Whitebox.setInternalState(handler, "config", mockConfig);
        Whitebox.setInternalState(handler, "relayKey", ZoomOAuth2Constants.RELAY_KEY.getValue());
        Whitebox.setInternalState(handler, "typeKey",
            OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue());
        Whitebox.setInternalState(handler, "authenticateUri",
            ZoomOAuth2Constants.AUTHENTICATE_URI.getValue());
        Whitebox.setInternalState(handler, "authorizeUriTemplate",
            ZoomOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue());
        Whitebox.setInternalState(handler, "client", ZoomOAuth2Constants.CLIENT_NAME.getValue());
        Whitebox.setInternalState(handler, "dataSource", mockDataSource);
        Whitebox.setInternalState(handler, "tokenCacheLifetime",
            Long.valueOf(OAuth2Constants.TOKEN_CACHE_LIFETIME.getValue()));
        return handler;
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#ZoomOAuth2Handler}<br>
     * Validates that the constructor configured some necessary properties.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testZoomOAuth2Handler() throws Exception {
        final OAuth2DataSource mockDataSource = EasyMock.createMock(OAuth2DataSource.class);

        PowerMock.mockStatic(OAuth2DataSource.class);
        expect(OAuth2DataSource.createDataSource(ZoomOAuth2Constants.CLIENT_NAME.getValue(),
            ZoomOAuth2Constants.HOST_ZOOM.getValue())).andReturn(mockDataSource);

        replay(mockConfig);
        PowerMock.replay(OAuth2DataSource.class);

        new ZoomOAuth2Handler(mockConfig);

        verify(mockConfig);
        PowerMock.verify(OAuth2DataSource.class);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#authorize}<br>
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
            ZoomOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(), clientId, encodedUri, "code",
            ZoomOAuth2Constants.REQUIRED_SCOPES.getValue());
        // expect a contact state with no relay
        final String expectedAuthorize = authorizeBase + stateValue;

        // expect buildStateString call
        expect(handler.buildStateString("&", "", "noop", "")).andReturn(stateValue);

        // expect buildAuthorize call
        expect(handler.buildAuthorizeUri(ZoomOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue(),
            null, "noop")).andReturn(authorizeBase);

        replay(handler);

        final String authorizeLocation = handler.authorize(params, null);

        // verify build was called
        verify(handler);

        assertNotNull(authorizeLocation);
        assertEquals(expectedAuthorize, authorizeLocation);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#authenticate}<br>
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

        mockOAuthInfo.setTokenUrl(matches(ZoomOAuth2Constants.AUTHENTICATE_URI.getValue()));
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
     * Test method for {@link ZoomOAuth2Handler#refresh}<br>
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

        mockOAuthInfo.setTokenUrl(matches(ZoomOAuth2Constants.AUTHENTICATE_URI.getValue()));
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

    /**
     * Test method for {@link ZoomOAuth2Handler#event}<br>
     * Validates that the event method calls deauthorize.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testEvent() throws Exception {
        final Map<String, String> headers = new HashMap<String, String>();
        final Map<String, Object> body = new HashMap<String, Object>();
        final Map<String, String> payload = new HashMap<String, String>();
        body.put("event", "app_deauthorized");
        body.put("payload", payload);
        final GuestRequest request = new GuestRequest(headers, body);

        final ZoomOAuth2Handler eventHandler = PowerMock
            .createPartialMockForAllMethodsExcept(ZoomOAuth2Handler.class, "event");
        // expect event to call deauthorize
        expect(eventHandler.deauthorize(headers, payload)).andReturn(true);

        replay(eventHandler);

        eventHandler.event(request);

        verify(eventHandler);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#deauthorize}<br>
     * Validates that the deauthorize method calls remove datasources and send compliance.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDeauthorize() throws Exception {
        final Account mockAccount = null;
        final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
        final String verificationToken = "auth-token";
        final String accountId = "account-id";
        final String userId = "user-id";
        final String identifier = accountId + "-" + userId;
        final String cacheKey = "prefix_" + identifier;
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), verificationToken);
        final Map<String, String> payload = new HashMap<String, String>();
        payload.put("account_id", accountId);
        payload.put("user_id", userId);
        payload.put("user_data_retention", "false");

        // expect to create an auth info container
        PowerMock.expectNew(OAuthInfo.class, Collections.emptyMap()).andReturn(mockOAuthInfo);
        // expect to load the zimbra account
        expect(handler.loadZimbraAccount(matches(accountId), matches(userId),
            anyObject(OAuthInfo.class))).andReturn(true);
        // expect to fetch the loaded info
        expect(mockOAuthInfo.getUsername()).andReturn(identifier);
        expect(mockOAuthInfo.getAccount()).andReturn(mockAccount);
        // expect to validate the request
        expect(handler.isValidEventRequest(anyObject(Account.class), eq(payload),
            matches(verificationToken), anyObject(OAuthInfo.class))).andReturn(true);
        // expect to remove relevant datasources
        expect(mockDataSource.removeDataSources(anyObject(Account.class), matches(identifier)))
            .andReturn(true);
        // expect to send a compliance request
        expect(handler.sendDataCompliance(eq(payload), anyObject(OAuthInfo.class))).andReturn(true);
        // expect to build a cache key
        expect(DataSourceMetaData.buildRootCacheKey(handler.client, identifier)).andReturn(cacheKey);
        // expect to remove the cache value
        expect(OAuth2CacheUtilities.remove(cacheKey)).andReturn(null);

        replay(handler);
        PowerMock.replay(OAuth2CacheUtilities.class);
        PowerMock.replay(OAuthInfo.class);
        PowerMock.replay(DataSourceMetaData.class);
        replay(mockOAuthInfo);
        replay(mockDataSource);

        assertEquals(true, handler.deauthorize(headers, payload));

        verify(handler);
        PowerMock.verify(OAuth2CacheUtilities.class);
        PowerMock.verify(OAuthInfo.class);
        PowerMock.verify(DataSourceMetaData.class);
        verify(mockOAuthInfo);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#deauthorize}<br>
     * Validates that the deauthorize method calls remove datasources but not
     * send compliance when the Disable-External-Requests header is present.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDeauthorizeDisableExternalRequests() throws Exception {
        final Account mockAccount = null;
        final OAuthInfo mockOAuthInfo = EasyMock.createMock(OAuthInfo.class);
        final String verificationToken = "auth-token";
        final String accountId = "account-id";
        final String userId = "user-id";
        final String identifier = accountId + "-" + userId;
        final String cacheKey = "prefix_" + identifier;
        final Map<String, String> headers = new HashMap<String, String>();
        headers.put(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), verificationToken);
        headers.put(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue(), "true");
        final Map<String, String> payload = new HashMap<String, String>();
        payload.put("account_id", accountId);
        payload.put("user_id", userId);
        payload.put("user_data_retention", "false");

        // expect to create an auth info container
        PowerMock.expectNew(OAuthInfo.class, Collections.emptyMap()).andReturn(mockOAuthInfo);
        // expect to load the zimbra account
        expect(handler.loadZimbraAccount(matches(accountId), matches(userId),
            anyObject(OAuthInfo.class))).andReturn(true);
        // expect to fetch the loaded info
        expect(mockOAuthInfo.getUsername()).andReturn(identifier);
        expect(mockOAuthInfo.getAccount()).andReturn(mockAccount);
        // expect to validate the request
        expect(handler.isValidEventRequest(anyObject(Account.class), eq(payload),
            matches(verificationToken), anyObject(OAuthInfo.class))).andReturn(true);
        // expect to remove relevant datasources
        expect(mockDataSource.removeDataSources(anyObject(Account.class), matches(identifier)))
            .andReturn(true);
        // expect to build a cache key
        expect(DataSourceMetaData.buildRootCacheKey(handler.client, identifier)).andReturn(cacheKey);
        // expect to remove the cache value
        expect(OAuth2CacheUtilities.remove(cacheKey)).andReturn(null);

        replay(handler);
        PowerMock.replay(OAuth2CacheUtilities.class);
        PowerMock.replay(OAuthInfo.class);
        PowerMock.replay(DataSourceMetaData.class);
        replay(mockOAuthInfo);
        replay(mockDataSource);

        assertEquals(true, handler.deauthorize(headers, payload));

        verify(handler);
        PowerMock.verify(OAuth2CacheUtilities.class);
        PowerMock.verify(OAuthInfo.class);
        PowerMock.verify(DataSourceMetaData.class);
        verify(mockOAuthInfo);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#isStorableTokenRefreshed}<br>
     * Validates that the method determines if the stored token has changed.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsStorableTokenRefreshed() throws Exception {
        final ZoomOAuth2Handler zoomHandler = PowerMock.createPartialMockForAllMethodsExcept(
            ZoomOAuth2Handler.class, "getStorableToken", "isStorableTokenRefreshed");
        final JsonNode credentials = OAuth2JsonUtilities
            .stringToJson(OAuth2JsonUtilities.objectToJson(
                ImmutableMap.of("refresh_token", "new-token", "access_token", "some-token")));

        assertTrue(zoomHandler.isStorableTokenRefreshed("stored", credentials));
        assertTrue(zoomHandler.isStorableTokenRefreshed("stored2345", credentials));
        assertTrue(zoomHandler.isStorableTokenRefreshed("new-token2345", credentials));
        assertFalse(zoomHandler.isStorableTokenRefreshed("new-token", credentials));
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#isStorableTokenRefreshed}<br>
     * Validates that the method does not return true if there is no refresh token.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsStorableTokenRefreshedNoRefreshToken() throws Exception {
        final ZoomOAuth2Handler zoomHandler = PowerMock.createPartialMockForAllMethodsExcept(
            ZoomOAuth2Handler.class, "getStorableToken", "isStorableTokenRefreshed");
        final JsonNode credentials = OAuth2JsonUtilities
            .stringToJson(OAuth2JsonUtilities.objectToJson(
                ImmutableMap.of("access_token", "some-token")));

        assertFalse(zoomHandler.isStorableTokenRefreshed("stored", credentials));
        assertFalse(zoomHandler.isStorableTokenRefreshed("new-token", credentials));
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#isProxyRequestAllowed}<br>
     * Validates that the method returns true with a valid target host.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowed() throws Exception {
        final ZoomOAuth2Handler zoomHandler = PowerMock.createPartialMockForAllMethodsExcept(
            ZoomOAuth2Handler.class, "isProxyRequestAllowed");
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer some-token");

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches("zoom.us"), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertTrue(zoomHandler.isProxyRequestAllowed(handler.client, HttpMethod.POST, extraHeaders,
            "https://zoom.us/", null, null));

        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#isProxyRequestAllowed}<br>
     * Validates that the method returns false with a blocked target host.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedBlockedHost() throws Exception {
        final ZoomOAuth2Handler zoomHandler = PowerMock.createPartialMockForAllMethodsExcept(
            ZoomOAuth2Handler.class, "isProxyRequestAllowed");
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer some-token");

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(anyObject(String.class), anyObject(Account.class)))
            .andReturn(false);

        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(zoomHandler.isProxyRequestAllowed(handler.client, HttpMethod.POST, extraHeaders,
            "https://blocked.example.test/", null, null));

        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is specified and token is not refreshable.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersWithIdentifierNonRefreshable() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final Map<String, String> tokens = ImmutableMap.of(identifier, accessToken);
        final String type = "noop";
        final OAuthInfo oauthInfo = new OAuthInfo(ImmutableMap.of("identifier", identifier));
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, identifier, type)).andReturn(tokens);
        expect(handler.isRefreshable()).andReturn(false).times(2);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is not specified and token is not refreshable.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersNoIdentifierNonRefreshable() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final Map<String, String> tokens = ImmutableMap.of(identifier, accessToken);
        final String type = "noop";
        final OAuthInfo oauthInfo = new OAuthInfo(Collections.emptyMap());
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, null, type)).andReturn(tokens);
        expect(handler.isRefreshable()).andReturn(false);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is not specified and token is in cache.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersNoIdentifierRefreshableFromCache() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final String refreshToken = "refresh-token";
        final String accountId = "account-id";
        final Map<String, String> tokens = ImmutableMap.of(identifier, refreshToken);
        final String type = "noop";
        final AuthToken mockZmAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo oauthInfo = new OAuthInfo(Collections.emptyMap());
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setZmAuthToken(mockZmAuthToken);
        final String cacheKey = "cache-key";

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, null, type)).andReturn(tokens);
        // expect to check if the client is refreshable
        expect(handler.isRefreshable()).andReturn(true);
        // expect to fetch the account id
        expect(mockZmAuthToken.getAccountId()).andReturn(accountId);
        // expect to build a cache key
        expect(DataSourceMetaData.buildTokenCacheKey(accountId, handler.client, identifier)).andReturn(cacheKey);
        // expect to fetch the access token from cache
        expect(OAuth2CacheUtilities.get(cacheKey)).andReturn(accessToken);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        PowerMock.replay(DataSourceMetaData.class);
        PowerMock.replay(OAuth2CacheUtilities.class);
        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);
        replay(mockZmAuthToken);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        PowerMock.verify(DataSourceMetaData.class);
        PowerMock.verify(OAuth2CacheUtilities.class);
        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
        verify(mockZmAuthToken);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is not specified and token is not in cache.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersNoIdentifierRefreshable() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final String refreshToken = "refresh-token";
        final String accountId = "account-id";
        final Map<String, String> tokens = ImmutableMap.of(identifier, refreshToken);
        final String type = "noop";
        final AuthToken mockZmAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo oauthInfo = new OAuthInfo(Collections.emptyMap());
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setZmAuthToken(mockZmAuthToken);
        oauthInfo.setAccessToken(accessToken);
        final String cacheKey = "cache-key";
        final ZoomOAuth2Handler handler = setupHandler("headers", "findStoredAccessToken",
            "findAndCacheStoredRefreshableAccessToken");

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, null, type)).andReturn(tokens);
        // expect to check if the client is refreshable
        expect(handler.isRefreshable()).andReturn(true);
        // expect to fetch the account id
        expect(mockZmAuthToken.getAccountId()).andReturn(accountId);
        // expect to build a cache key
        expect(DataSourceMetaData.buildTokenCacheKey(accountId, handler.client, identifier))
            .andReturn(cacheKey);
        // expect to fail to fetch the access token from cache
        expect(OAuth2CacheUtilities.get(cacheKey)).andReturn(null);
        // expect to call refresh
        expect(handler.refresh(anyObject(OAuthInfo.class))).andReturn(true);
        // expect to cache the access token
        expect(OAuth2CacheUtilities.put(cacheKey, accessToken, handler.tokenCacheLifetime))
            .andReturn(accessToken);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        PowerMock.replay(DataSourceMetaData.class);
        PowerMock.replay(OAuth2CacheUtilities.class);
        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);
        replay(mockZmAuthToken);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        PowerMock.verify(DataSourceMetaData.class);
        PowerMock.verify(OAuth2CacheUtilities.class);
        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
        verify(mockZmAuthToken);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is specified and token is in cache.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersWithIdentifierRefreshable() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final String accountId = "account-id";
        final AuthToken mockZmAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo oauthInfo = new OAuthInfo(ImmutableMap.of("identifier", identifier));
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setZmAuthToken(mockZmAuthToken);
        oauthInfo.setAccessToken(accessToken);
        final String cacheKey = "cache-key";
        final ZoomOAuth2Handler handler = setupHandler("headers", "findStoredAccessToken",
            "findAndCacheStoredRefreshableAccessToken");

        // expect to check if the client is refreshable
        expect(handler.isRefreshable()).andReturn(true);
        // expect to fetch the account id
        expect(mockZmAuthToken.getAccountId()).andReturn(accountId);
        // expect to build a cache key
        expect(DataSourceMetaData.buildTokenCacheKey(accountId, handler.client, identifier))
            .andReturn(cacheKey);
        // expect to fail to fetch the access token from cache
        expect(OAuth2CacheUtilities.get(cacheKey)).andReturn(null);
        // expect to call refresh
        expect(handler.refresh(anyObject(OAuthInfo.class))).andReturn(true);
        // expect to cache the access token
        expect(OAuth2CacheUtilities.put(cacheKey, accessToken, handler.tokenCacheLifetime))
            .andReturn(accessToken);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        PowerMock.replay(DataSourceMetaData.class);
        PowerMock.replay(OAuth2CacheUtilities.class);
        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);
        replay(mockZmAuthToken);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        PowerMock.verify(DataSourceMetaData.class);
        PowerMock.verify(OAuth2CacheUtilities.class);
        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
        verify(mockZmAuthToken);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method fetches the auth header
     * when identifier is specified but token is not in cache.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testHeadersWithIdentifierRefreshableFromCache() throws Exception {
        final String identifier = "test-user@localhost";
        final String accessToken = "access-token";
        final String authHeader = String.format("Bearer %s", accessToken);
        final String accountId = "account-id";
        final AuthToken mockZmAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo oauthInfo = new OAuthInfo(ImmutableMap.of("identifier", identifier));
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setZmAuthToken(mockZmAuthToken);
        oauthInfo.setAccessToken(accessToken);
        final String cacheKey = "cache-key";
        final ZoomOAuth2Handler handler = setupHandler("headers", "findStoredAccessToken",
            "findAndCacheStoredRefreshableAccessToken");

        // expect to check if the client is refreshable
        expect(handler.isRefreshable()).andReturn(true);
        // expect to fetch the account id
        expect(mockZmAuthToken.getAccountId()).andReturn(accountId);
        // expect to build a cache key
        expect(DataSourceMetaData.buildTokenCacheKey(accountId, handler.client, identifier))
            .andReturn(cacheKey);
        // expect to fetch the access token from cache
        expect(OAuth2CacheUtilities.get(cacheKey)).andReturn(accessToken);
        // expect to build the auth header
        expect(handler.buildAuthorizationHeader(accessToken)).andReturn(authHeader);

        PowerMock.replay(DataSourceMetaData.class);
        PowerMock.replay(OAuth2CacheUtilities.class);
        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);
        replay(mockZmAuthToken);

        final Map<String, String> headers = handler.headers(oauthInfo);
        assertNotNull(headers);
        // expect to find the auth header
        assertEquals(authHeader, headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()));
        // expect to find the user agent header
        assertEquals(OAuth2HttpConstants.PROXY_USER_AGENT.getValue(),
            headers.get(OAuth2HttpConstants.HEADER_USER_AGENT.getValue()));

        PowerMock.verify(DataSourceMetaData.class);
        PowerMock.verify(OAuth2CacheUtilities.class);
        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
        verify(mockZmAuthToken);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method throws an exception
     * if no auth is found when identifier is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test(expected=ServiceException.class)
    public void testHeadersWithIdentifierNoAuthFound() throws Exception {
        final String identifier = "test-user@localhost";
        final String type = "noop";
        final OAuthInfo oauthInfo = new OAuthInfo(ImmutableMap.of("identifier", identifier));
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, identifier, type)).andReturn(Collections.emptyMap());
        expect(handler.isRefreshable()).andReturn(false);

        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);

        handler.headers(oauthInfo);

        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
    }

    /**
     * Test method for {@link ZoomOAuth2Handler#headers}<br>
     * Validates that the headers method throws an exception
     * if no auth is found when no identifier is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test(expected=ServiceException.class)
    public void testHeadersNoIdentifierNoAuthFound() throws Exception {
        final String identifier = "test-user@localhost";
        final Map<String, String> tokens = ImmutableMap.of(identifier, "token");
        final String type = "noop";
        final AuthToken mockZmAuthToken = EasyMock.createMock(AuthToken.class);
        final OAuthInfo oauthInfo = new OAuthInfo(Collections.emptyMap());
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setZmAuthToken(mockZmAuthToken);
        final String accountId = "account-id";
        final String cacheKey = "cache-key";
        final ZoomOAuth2Handler handler = setupHandler("headers", "findStoredAccessToken",
            "findAndCacheStoredRefreshableAccessToken");

        // expect to fetch refresh tokens
        expect(mockDataSource.getRefreshTokens(null, null, type)).andReturn(tokens);
        // expect to check if the client is refreshable
        expect(handler.isRefreshable()).andReturn(true);
        // expect to fetch the account id
        expect(mockZmAuthToken.getAccountId()).andReturn(accountId);
        // expect to build a cache key
        expect(DataSourceMetaData.buildTokenCacheKey(accountId, handler.client, identifier))
            .andReturn(cacheKey);
        // expect to fail to fetch the access token from cache
        expect(OAuth2CacheUtilities.get(cacheKey)).andReturn(null);
        // expect to call refresh
        expect(handler.refresh(anyObject(OAuthInfo.class)))
            .andThrow(ServiceException.INVALID_REQUEST("no datasource found", null));

        PowerMock.replay(DataSourceMetaData.class);
        PowerMock.replay(OAuth2CacheUtilities.class);
        replay(handler);
        replay(mockConfig);
        replay(mockDataSource);
        replay(mockZmAuthToken);

        handler.headers(oauthInfo);

        PowerMock.verify(DataSourceMetaData.class);
        PowerMock.verify(OAuth2CacheUtilities.class);
        verify(handler);
        verify(mockConfig);
        verify(mockDataSource);
        verify(mockZmAuthToken);
    }
}
