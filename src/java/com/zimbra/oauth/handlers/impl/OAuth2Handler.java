/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.zimbra.client.ZMailbox;
import com.zimbra.client.ZMailbox.Options;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.ZimbraAuthToken;
import com.zimbra.cs.util.AccountUtil;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.handlers.IOAuth2ProxyHandler;
import com.zimbra.oauth.models.GuestRequest;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2CacheUtilities;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2DataSource.DataSourceMetaData;
import com.zimbra.oauth.utilities.OAuth2ErrorConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ProxyUtilities;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The OAuth2Handler class.<br>
 * Base OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public abstract class OAuth2Handler {

    public static final String RELAY_DELIMETER = ";";
    /**
     * Social app name
     */
    protected String client;

    /**
     * Implementation authenticate uri.
     */
    protected String authenticateUri;

    /**
     * Implementation authorize uri template.
     */
    protected String authorizeUriTemplate;

    /**
     * Implementation required authorization scopes.
     */
    protected String requiredScopes;

    /**
     * Implementation authorization scope delimiter.
     */
    protected String scopeDelimiter;

    /**
     * Implementation relay key.
     */
    protected String relayKey;

    /**
     * Implementation type key.
     */
    protected String typeKey;

    /**
     * DataSource handler for the implementation.
     */
    protected final OAuth2DataSource dataSource;

    /**
     * Configuration object.
     */
    protected final Configuration config;

    /**
     * Implementation token lifetime in cache (seconds).
     */
    protected long tokenCacheLifetime;

    /**
     * Constructor.
     *
     * @param config A configuration object
     * @param client The app client name (yahoo, facebook, google, etc)
     * @param clientHost The hostname associated with the client
     */
    public OAuth2Handler(Configuration config, String client, String clientHost) {
        this.client = client;
        this.config = config;
        typeKey = OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue();
        dataSource = OAuth2DataSource.createDataSource(client, clientHost);
        tokenCacheLifetime = Long.valueOf(OAuth2Constants.TOKEN_CACHE_LIFETIME.getValue());
    }

    /**
     * Validates that the token response has no errors, and contains the
     * requested access information for this implementation.
     *
     * @param response The get_token response to validate
     * @throws ServiceException If there are issues with the response
     */
    protected abstract void validateTokenResponse(JsonNode response) throws ServiceException;

    /**
     * This method should be overridden if the implementing client
     * expects a different token response on refresh.
     *
     * @see #validateTokenResponse(JsonNode)
     */
    protected void validateRefreshTokenResponse(JsonNode response)
        throws ServiceException {
        // validate as regular token response by default
        validateTokenResponse(response);
    }

    /**
     * This method should be overridden if the implementing client cannot use the
     * standard getTokenRequest implementation.
     *
     * @see OAuth2Handler#getTokenRequest(OAuthInfo, String)
     */
    protected JsonNode getToken(OAuthInfo authInfo, String basicToken) throws ServiceException {
        return getTokenRequest(authInfo, basicToken);
    }

    /**
     * Default get_token implementation, usable by standard oauth2 services.<br>
     * Builds and executes the get_token HTTP request for the client.
     *
     * @param authInfo Contains the auth info to use in the request
     * @param basicToken The basic authorization header
     * @return Json response from the endpoint containing credentials
     * @throws ServiceException If there are issues performing the request or
     *             parsing for json
     */
    public static JsonNode getTokenRequest(OAuthInfo authInfo, String basicToken)
        throws ServiceException {
        final String refreshToken = authInfo.getRefreshToken();
        final HttpPost request = new HttpPost(authInfo.getTokenUrl());
        final List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            params.add(new BasicNameValuePair("grant_type", "refresh_token"));
            params.add(new BasicNameValuePair("refresh_token", refreshToken));
        } else {
            // otherwise use the code
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", authInfo.getParam("code")));
        }
        params.add(new BasicNameValuePair("redirect_uri", authInfo.getClientRedirectUri()));
        params.add(new BasicNameValuePair("client_secret", authInfo.getClientSecret()));
        params.add(new BasicNameValuePair("client_id", authInfo.getClientId()));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            "Basic " + basicToken);
        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
            ZimbraLog.extensions.debug("Request for auth token completed.");
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization token.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization token for this user.");
        }

        return json;
    }

    /**
     * Builds the passed in authorize uri template with configured values.<br>
     * Required configured implementation properties: `clientRedirectUri`,
     * `clientId`, `scope`.
     *
     * @param template The authorize uri template for this implementation
     * @param account The account to acquire configuration by access level
     * @param datasourceType The type of datasource we're authorizing to create
     * @return The authorize uri
     * @throws ServiceException If there are issues with the app configuration
     *             (missing credentials)
     */
    protected String buildAuthorizeUri(String template, Account account, String datasourceType)
        throws ServiceException {
        final String responseType = "code";
        String encodedRedirectUri = "";
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(), client), client,
            account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(), client),
            client, account);
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.NOT_FOUND(String.format(
                "The oauth client: %s is not properly configured. Please set oauth credentials and redirect uri.",
                client), new Exception("Invalid config"));
        }

        final String scopeIdentifier = StringUtils.isEmpty(datasourceType)
            ? client
            : client + "_" + datasourceType;
        final String scope = StringUtils.join(new String[] { requiredScopes,
            config.getString(String.format(OAuth2ConfigConstants.LC_OAUTH_SCOPE_TEMPLATE.getValue(),
                client), scopeIdentifier, account) },
            scopeDelimiter);

        try {
            encodedRedirectUri = URLEncoder.encode(clientRedirectUri,
                OAuth2Constants.ENCODING.getValue());
        } catch (final UnsupportedEncodingException e) {
            ZimbraLog.extensions.errorQuietly("Invalid redirect URI found in client config.", e);
        }

        return String.format(template, clientId, encodedRedirectUri, responseType, scope);
    }

    /**
     * @see IOAuth2Handler#authorize(String, Account)
     */
    public String authorize(Map<String, String> params, Account account) throws ServiceException {
        final String relay = StringUtils.defaultString(params.get(relayKey), "");
        final String type = StringUtils.defaultString(params.get(typeKey), "");
        final String jwt = StringUtils
            .defaultString(params.get(OAuth2HttpConstants.JWT_PARAM_KEY.getValue()), "");
        final String relayValue = buildStateString("&", relay, type, jwt);

        return buildAuthorizeUri(authorizeUriTemplate, account, type) + relayValue;
    }

    /**
     * @see IOAuth2Handler#authenticate(OAuthInfo)
     */
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        final String basicToken = OAuth2Utilities.encodeBasicHeader(
            oauthInfo.getClientId(), oauthInfo.getClientSecret());
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getToken(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateTokenResponse(credentials);
        // determine account associated with credentials
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken(), account);

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(getStorableToken(credentials));
        dataSource.syncDatasource(mailbox, oauthInfo, getDatasourceCustomAttrs(oauthInfo));

        oauthInfo.setClientSecret(null);
        // allow clients to set response params
        setResponseParams(credentials, oauthInfo);

        return true;
    }

    /**
     * @see IOAuth2Handler#refresh(OAuthInfo)
     */
    public Boolean refresh(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        final String identifier = oauthInfo.getUsername();
        final String type = oauthInfo.getParam(typeKey);
        if (StringUtils.isEmpty(identifier) || StringUtils.isEmpty(type)) {
            throw ServiceException.INVALID_REQUEST(
                String.format("Missing arguments: identifier: %s, type: %s", identifier, type),
                null);
        }
        loadClientConfig(account, oauthInfo);

        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken(), account);
        String refreshToken = oauthInfo.getRefreshToken();
        // fetch the refresh token if it isn't set already
        if (StringUtils.isEmpty(refreshToken)) {
            refreshToken = dataSource.getRefreshToken(mailbox, identifier, type);
            if (StringUtils.isEmpty(refreshToken)) {
                ZimbraLog.extensions.debug("No refresh token found for identifier: %s, and type: %s.",
                    identifier, type);
                throw ServiceException.INVALID_REQUEST(
                    String.format("No refresh token found for identifier: %s, and type: %s.",
                        identifier, type),
                    null);
            }
            oauthInfo.setRefreshToken(refreshToken);
        }

        final String basicToken = OAuth2Utilities.encodeBasicHeader(
            oauthInfo.getClientId(), oauthInfo.getClientSecret());
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getToken(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateRefreshTokenResponse(credentials);
        ZimbraLog.extensions.trace("Refresh performed for: %s", identifier);

        // update the refresh token if it has changed (some of them change on every use)
        if (isStorableTokenRefreshed(refreshToken, credentials)) {
            oauthInfo.setRefreshToken(getStorableToken(credentials));
            ZimbraLog.extensions.debug("Updating oauth datasource with a new token");
            dataSource.syncDatasource(mailbox, oauthInfo, getDatasourceCustomAttrs(oauthInfo));
        } else {
            dataSource.clearTokensCache(oauthInfo);
        }
        oauthInfo.setAccessToken(getUsableToken(credentials));
        oauthInfo.setClientSecret(null);
        // allow clients to set response params
        setResponseParams(credentials, oauthInfo);

        return true;
    }

    /**
     * @see IOAuth2Handler#info(OAuthInfo)
     */
    public Boolean info(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        loadClientConfig(account, oauthInfo);
        oauthInfo.setClientSecret(null);

        // only these params will be returned to the client
        oauthInfo.setParams(Collections.singletonMap("client_id", oauthInfo.getClientId()));
        return true;
    }

    /**
     * @see IOAuth2Handler#event(GuestRequest)
     */
    public Boolean event(GuestRequest request) throws ServiceException {
        ZimbraLog.extensions.debug("Event is not supported by this client: %s.", client);
        throw ServiceException.UNSUPPORTED();
    }

    /**
     * @see IOAuth2ProxyHandler#headers(OAuthInfo)
     */
    public Map<String, String> headers(OAuthInfo oauthInfo) throws ServiceException {
        final String accessToken = findStoredAccessToken(oauthInfo);
        return ImmutableMap.of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            buildAuthorizationHeader(accessToken),
            OAuth2HttpConstants.HEADER_USER_AGENT.getValue(),
            OAuth2HttpConstants.PROXY_USER_AGENT.getValue());
    }

    /**
     * @see IOAuth2ProxyHandler#isProxyRequestAllowed(String, String, Map, String, byte[], Account)
     */
    public boolean isProxyRequestAllowed(String client, String method,
        Map<String, String> extraHeaders, String target, byte[] body, Account account) {
        URIBuilder builder;
        try {
            builder = new URIBuilder(target);
        } catch (final URISyntaxException e) {
            ZimbraLog.extensions.warn("Unable to parse proxy target: %s", target);
            return false;
        }
        return OAuth2ProxyUtilities.isAllowedTargetHost(builder.getHost(), account);
    }

    /**
     * Attempts to find an access token if no identifier is provided or the client
     * stores non-refreshable tokens. Fetches token from cache or full refresh otherwise.
     *
     * @param oauthInfo May or may not contain an identifier to validate against datasources
     * @return An access token either newly refreshed, or from cache
     * @throws ServiceException If there are issues
     */
    protected String findStoredAccessToken(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        String identifier = oauthInfo.getParam("identifier");
        final String type = OAuth2Constants.DEFAULT_PROXY_TYPE.getValue();

        // find the identifier if none specified or find the access token if non refreshable
        if (StringUtils.isEmpty(identifier) || !isRefreshable()) {
            final Map<String, String> tokens = dataSource.getRefreshTokens(account, identifier, type);
            // ensure there is only one if no identifier was specified
            final int tokensFound = tokens.size();
            if (tokensFound != 1) {
                final String message = String.format(
                    "%d tokens found for identifier: %s type: %s client: %s", tokensFound,
                    identifier, type, client);
                ZimbraLog.extensions.debug(message);
                throw ServiceException.INVALID_REQUEST(message, null);
            }
            identifier = tokens.keySet().iterator().next();
            // we're done if the token is not refreshable
            if (!isRefreshable()) {
                return tokens.get(identifier);
            }
            oauthInfo.setRefreshToken(tokens.get(identifier));
        }
        // identifier was found or specified, client is non refreshable
        oauthInfo.setUsername(identifier);
        return findAndCacheStoredRefreshableAccessToken(oauthInfo);
    }

    /**
     * Fetches access token from cache, refreshes/caches if it's missing.
     *
     * @param oauthInfo Must contain zm auth token, zimbra account, username (identifier)
     * @return An access token either newly refreshed, or from cache
     * @throws ServiceException If there are issues
     * @see #refresh(OAuthInfo)
     */
    protected String findAndCacheStoredRefreshableAccessToken(OAuthInfo oauthInfo)
        throws ServiceException {
        final String accountId = oauthInfo.getZmAuthToken().getAccountId();
        final String identifier = oauthInfo.getUsername();
        final String type = OAuth2Constants.DEFAULT_PROXY_TYPE.getValue();
        final String cacheKey = DataSourceMetaData.buildTokenCacheKey(accountId, client,
            identifier);
        // check cache
        String accessToken = OAuth2CacheUtilities.get(cacheKey);
        if (!StringUtils.isEmpty(accessToken)) {
            ZimbraLog.extensions.debug("Using cached access token for oauth proxy.");
            return accessToken;
        }

        oauthInfo.setParams(ImmutableMap.of(typeKey, type));
        refresh(oauthInfo);
        accessToken = oauthInfo.getAccessToken();

        // cache the access token (this may clobber if many requests are refreshing)
        return OAuth2CacheUtilities.put(cacheKey, accessToken, tokenCacheLifetime);
    }

    /**
     * This method should be overridden if the implementing client does not store a refresh token.
     *
     * @return True if this implementation stores a refresh token
     */
    protected boolean isRefreshable() {
        return true;
    }

    /**
     * Sets response parameters to return to the resource for use in redirect.<br>
     * This method should be overridden if the implementing client returns
     * different parameters.
     *
     * @param tokenResponse The get token response
     * @param oauthInfo The oauthInfo to set the response params on
     */
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        if ("noop".equalsIgnoreCase(oauthInfo.getParam("type"))) {
            params.put("access_token", tokenResponse.get("access_token").asText());
            params.put("email", oauthInfo.getUsername());
        }
        oauthInfo.setParams(params);
    }

    /**
     * Get the token to store in datasource - defaults to refresh token.<br>
     * This method should be overridden if the implementing client stores a different parameter.
     *
     * @param credentials The validated getToken response to retrieve token from
     * @return The token to store
     */
    protected String getStorableToken(JsonNode credentials) {
        return credentials.hasNonNull("refresh_token")
            ? credentials.get("refresh_token").asText()
            : null;
    }

    /**
     * This method should be overridden if the implementing client uses a different parameter.
     *
     * @param credentials The validated getToken response to retrieve token from
     * @return The token that may be used in requests to client services
     */
    protected String getUsableToken(JsonNode credentials) {
        return credentials.hasNonNull("access_token")
            ? credentials.get("access_token").asText()
            : null;
    }

    /**
     * This method should be overridden if the implementing client uses a different auth header.
     *
     * @param accessToken The stored or refreshed token depending on implementation
     * @return An authorization header that may be used in requests to client services
     */
    protected String buildAuthorizationHeader(String accessToken) {
        return String.format("Bearer %s", accessToken);
    }

    /**
     * Determines if the datasource needs to be updated on refresh.<br>
     * This method should be overridden if the implementing client has different refresh criteria.
     *
     * @param storedToken The current refresh token
     * @param credentials The token response
     * @return True if the refresh token needs to be updated
     */
    protected boolean isStorableTokenRefreshed(String storedToken, JsonNode credentials) {
        final String newToken = getStorableToken(credentials);
        // some clients won't return a refreshToken on refresh
        // so check that the new token both exists and is new
        return newToken != null && !"null".equals(newToken) && !newToken.equals(storedToken);
    }

    /**
     * Loads client config for oauth into the specified auth info object.
     *
     * @param account The account to use when fetching config
     * @param authInfo The auth info to update
     * @throws ServiceException If any of the credentials are missing
     */
    protected void loadClientConfig(Account account, OAuthInfo authInfo) throws ServiceException {
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(), client), client,
            account);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(), client),
            client, account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(), client),
            client, account);
        // error if missing any
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret)
            || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.NOT_FOUND(String.format(
                "The oauth client: %s is not properly configured. Please set oauth credentials and redirect uri.",
                client), new Exception("Invalid config"));
        }
        // update the existing auth info
        authInfo.setClientId(clientId);
        authInfo.setClientSecret(clientSecret);
        authInfo.setClientRedirectUri(clientRedirectUri);
    }

    /**
     * Default getPrimaryEmail implementation. May be used by clients that
     * return an `id_token` in the get_token request - otherwise this method
     * must be overridden.<br>
     * Retrieves the social service account primary email from the `id_token`.
     *
     * @param credentials The get_token response containing an id_token
     * @param account The account to acquire configuration by access level
     * @return The primary email address associated with the credentials
     * @throws ServiceException If there are issues determining the primary
     *             address
     */
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        final DecodedJWT jwt = JWT.decode(credentials.get("id_token").asText());
        final Claim emailClaim = jwt.getClaim("email");
        if (emailClaim == null || StringUtils.isEmpty(emailClaim.asString())) {
            throw ServiceException.PARSE_ERROR("Authentication response is missing primary email.",
                null);
        }
        return emailClaim.asString();
    }

    /**
     * Declares the query params to look for on oauth2 authenticate
     * callback.<br>
     * This method should be overridden if the implementing client uses
     * different parameters.
     *
     * @see IOAuth2Handler#getAuthenticateParamKeys()
     */
    public List<String> getAuthenticateParamKeys() {
        // code, error, state are default oauth2 keys
        return Arrays.asList("code", "error", relayKey);
    }

    /**
     * Declares the query params to look for on oauth2 authorize
     * callback.<br>
     * This method should be overridden if the implementing client uses
     * different parameters.
     *
     * @see IOAuth2Handler#getAuthenticateParamKeys()
     */
    public List<String> getAuthorizeParamKeys() {
        return Arrays.asList(relayKey, typeKey);
    }

    /**
     * @see IOAuth2ProxyHandler#getHeadersParamKeys()
     */
    public List<String> getHeadersParamKeys() {
        return ImmutableList.of("identifier", "target");
    }

    /**
     * Default param verifier for authenticate.<br>
     * Ensures a relay is passed in with the ds type,
     * then delegates to handle client specific params.
     *
     * @see IOAuth2Handler#verifyAndSplitAuthenticateParams()
     */
    public void verifyAndSplitAuthenticateParams(Map<String, String> params)
        throws ServiceException {
        // invalid if no state param since we need `type`
        if (!params.containsKey(relayKey)) {
            throw ServiceException
                .INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
        }

        // split available params before checking for errors
        splitStateString(params.get(relayKey), params);

        // check for client specific errors
        verifyAuthenticateParams(params);
    }

    /**
     * Default param verifier for authorize.<br>
     * This method should be overridden if the implementing client expects
     * different parameters.
     *
     * @throws ServiceException If there are issues verifying type
     *
     * @see IOAuth2Handler#verifyAuthorizeParams(Map)
     */
    public void verifyAuthorizeParams(Map<String, String> params) throws ServiceException {
        final String relay = params.get(relayKey);
        if (!StringUtils.isEmpty(relay)) {
            ZimbraLog.extensions.debug("Relay not passed in authorize request");
        }
        final String type = params.get(typeKey);
        if (StringUtils.isEmpty(type)) {
            ZimbraLog.extensions.debug("\"type\" not received in authorize request");
            throw ServiceException.INVALID_REQUEST("Missing type param in authorize request.", null);
        } else {
            //validate if type is valid
            DataSourceMetaData.getDataSourceType(type);
        }
    }

    /**
     * Default param verifier for authenticate.<br>
     * Ensures configurable params are in a specific state.<br>
     * This method should be overridden if the implementing client
     * expects different params than the default.
     *
     * @param params Map of params to check
     * @throws ServiceException If client specific params are not valid
     */
    protected void verifyAuthenticateParams(Map<String, String> params) throws ServiceException {
        // ensure no errors exist
        final String error = params.get("error");
        if (!StringUtils.isEmpty(error)) {
            throw ServiceException.PERM_DENIED(error);
            // ensure code exists
        } else if (!params.containsKey("code")) {
            throw ServiceException
                .INVALID_REQUEST(OAuth2ErrorConstants.ERROR_INVALID_AUTH_CODE.getValue(), null);
        }
    }

    /**
     * Builds a state string with given input.<br>
     * The state string may be returned in the authorize response location
     * when directing the requester to the social service's endpoint.
     *
     * @param prefix Query key prefix (&, ?)
     * @param relay The redirect
     * @param type The datasource type (contact, caldav)
     * @param jwt A jwt
     * @return The state string
     * @throws ServiceException If any input is invalid (required and missing, invalid redirect, etc)
     */
    protected String buildStateString(String prefix, String relay, String type, String jwt)
        throws ServiceException {
        // TODO: make a utility class that handles ordering, naming,
        // optional, required, etc for parsing back and forth between
        // authorize keys and authenticate state data
        String relayValue = "";
        // relay is first and optional
        if (!relay.isEmpty()) {
            try {
                relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to decode relay parameter.", e);
            }

            try {
                relayValue = prefix + relayKey + "="
                    + URLEncoder.encode(relay, OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to encode relay parameter.", e);
            }
        }

        // type is second and required before we arrive in this method
        if (!type.isEmpty()) {
            try {
                if (relayValue.isEmpty()) {
                    relayValue = prefix + relayKey + "=";
                }
                relayValue += URLEncoder.encode(RELAY_DELIMETER + type,
                    OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to encode type parameter.", e);
            }
        } else {
            ZimbraLog.extensions.error("Missing data source type");
            throw ServiceException.FAILURE("Missing data source type", null);
        }

        // jwt is third and optional
        if (!jwt.isEmpty()) {
            try {
                relayValue += URLEncoder.encode(RELAY_DELIMETER + jwt,
                    OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to encode jwt parameter.", e);
            }
        }
        return relayValue;
    }

    /**
     * Splits a state string for expected key/value pairs,
     * then adds them to the passed in params.
     *
     * @param state The string to split
     * @param params The map to update
     * @throws ServiceException If there are invalid pairs
     */
    protected void splitStateString(String state, Map<String, String> params)
        throws ServiceException {
        if (state != null && params != null) {
            final String[] origVal = state.split(RELAY_DELIMETER);
            if (origVal.length < 2) {
                throw ServiceException
                    .INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
            }
            // store the redirect location even if empty
            params.put(relayKey, origVal[0]);
            // ensure type exists
            if (origVal[1].isEmpty()) {
                throw ServiceException
                    .INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
            } else {
                ZimbraLog.extensions.debug("Adding %s = %s", typeKey, origVal[1]);
                params.put(typeKey, origVal[1]);
            }
            // store the jwt if exists and not empty
            if (origVal.length > 2 && !StringUtils.isEmpty(origVal[2])) {
                params.put(OAuth2HttpConstants.JWT_PARAM_KEY.getValue(), origVal[2]);
            }
        }
    }

    /**
     * Returns the relay state param for the client.<br>
     * This method should be overridden if the implementing client uses a
     * different key for relay.
     *
     * @see IOAuth2Handler#getRelay()
     */
    public String getRelay(Map<String, String> params) {
        return params.get(relayKey);
    }

    /**
     * Executes an Http Request and parses for json.
     *
     * @param request Request to execute
     * @return The json response
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static JsonNode executeRequestForJson(HttpRequestBase request)
        throws ServiceException, IOException {
        JsonNode json = null;
        final String responseBody = OAuth2Utilities.executeRequest(request);

        // try to parse json
        // throw if the upstream response
        // is not what we previously expected
        try {
            json = stringToJson(responseBody);
        } catch (final JsonParseException e) {
            ZimbraLog.extensions.warn("The destination server responded with unexpected data.");
            throw ServiceException
                .PROXY_ERROR("The destination server responded with unexpected data.", null);
        }

        return json;
    }

    /**
     * Wrapper for tests.
     *
     * @see OAuth2JsonUtilities#stringToJson(String)
     */
    protected static JsonNode stringToJson(String jsonString) throws IOException {
        return OAuth2JsonUtilities.stringToJson(jsonString);
    }

    /**
     * Sets a specified form encoded param entity on the request.
     *
     * @param request The request to set the entity on
     * @param params The params to set
     * @throws ServiceException If there are issues encoding
     */
    public static void setFormEntity(HttpPost request, List<NameValuePair> params)
        throws ServiceException {
        try {
            request.setEntity(new UrlEncodedFormEntity(params));
        } catch (final UnsupportedEncodingException e) {
            ZimbraLog.extensions.error("Unable to encode token request params %s", params);
            ZimbraLog.extensions.debug(e);
            throw ServiceException.INVALID_REQUEST("Unable to encode token request params.", null);
        }
    }

    /**
     * Retrieves the Zimbra mailbox via specified auth token.<br>
     * Fetches the soap uri for the specified account.
     *
     * @param zmAuthToken The Zimbra auth token to identify the account with
     * @param account Instance of the account we want a mailbox for
     * @return The Zimbra mailbox
     * @throws ServiceException If there is an issue retrieving the account
     *             mailbox
     */
    protected ZMailbox getZimbraMailbox(AuthToken zmAuthToken, Account account) throws ServiceException {
        // create a mailbox by auth token
        try {
            // fetch soap uri via the account for multi-node envs
            final String zimbraSoapUri = AccountUtil.getSoapUri(account);
            ZimbraLog.extensions.debug("Creating ZMailbox for account: %s, soap uri: %s",
                account.getName(), zimbraSoapUri);
            final Options options = new Options();
            options.setUri(zimbraSoapUri);
            final ZMailbox mbox = new ZMailbox(options);
            // get a csrf unsecured token since we are internal
            final AuthToken csrfUnsafeToken = ZimbraAuthToken
                .getCsrfUnsecuredAuthToken(zmAuthToken);
            mbox.initAuthToken(csrfUnsafeToken.toZAuthToken());
            return mbox;
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue acquiring the mailbox using the specified auth token.", e);
            throw e;
        }
    }

    /**
     * Hook to provide data source specific attributes for data source creation.<br>
     * This method should be overridden if the implementing client expects non-null.
     *
     * @param oauthInfo Contains information used to determine custom attributes
     * @return Map of custom datasource attributes to set
     * @throws ServiceException If there are any issues
     */
    protected Map<String, Object> getDatasourceCustomAttrs(OAuthInfo oauthInfo) throws ServiceException {
        return null;
    }
}
