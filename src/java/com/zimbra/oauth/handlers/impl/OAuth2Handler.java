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
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ConnectionPoolTimeoutException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.httpclient.HttpProxyUtil;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;
import com.zimbra.oauth.utilities.OAuthDataSource;

/**
 * The OAuth2Handler class.<br>
 * Base OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public abstract class OAuth2Handler {

    /**
     * Implementation client id.
     */
    protected final String clientId;

    /**
     * Implementation client secret.
     */
    protected final String clientSecret;

    /**
     * Implementation redirect uri.
     */
    protected final String clientRedirectUri;

    /**
     * Implementation Basic header.
     */
    protected final String basicToken;

    /**
     * Implementation token scope.
     */
    protected String scope = "";

    /**
     * Implementation authorize uri.<br>
     * Expected template format pattern key order:
     * {client_id}{redirect_uri}{response_type}{scope}<br>
     * Relay is appended to the end by default.
     */
    protected String authorizeUri;

    /**
     * Implementation authenticate uri.
     */
    protected String authenticateUri;

    /**
     * Implementation relay key.
     */
    protected String relayKey;

    /**
     * DataSource handler for the implementation.
     */
    protected final OAuthDataSource dataSource;

    /**
     * Configuration object.
     */
    protected final Configuration config;

    /**
     * A mapper object that can convert between Java <-> JSON objects.
     */
    protected static final ObjectMapper mapper = OAuth2Utilities.createDefaultMapper();

    /**
     * A URI string for the Zimbra host.
     */
    protected final String zimbraHostUri;

    /**
     * Constructor.
     *
     * @param config A configuration object
     */
    public OAuth2Handler(Configuration config, String client, String clientHost) {
        this.config = config;
        clientId = config
            .getString(String.format(OAuth2Constants.LC_OAUTH_CLIENT_ID_TEMPLATE, client));
        clientSecret = config
            .getString(String.format(OAuth2Constants.LC_OAUTH_CLIENT_SECRET_TEMPLATE, client));
        clientRedirectUri = config.getString(
            String.format(OAuth2Constants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE, client));
        basicToken = OAuth2Utilities.encodeBasicHeader(clientId, clientSecret);
        dataSource = OAuthDataSource.createDataSource(client, clientHost);
        final String zimbraHostname = config.getString(OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME);
        // warn if missing hostname
        if (StringUtils.isEmpty(zimbraHostname)) {
            ZimbraLog.extensions.warn("The zimbra server hostname is not configured.");
        }
        // cache the host uri
        zimbraHostUri = String.format(config.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE,
            OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE), zimbraHostname);
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
     * Get an instance of HttpClient which is configured to use Zimbra proxy.
     *
     * @return HttpClient A HttpClient instance
     */
    protected static HttpClient getHttpClient() {
        final HttpClient httpClient = ZimbraHttpConnectionManager.getExternalHttpConnMgr()
            .newHttpClient();
        HttpProxyUtil.configureProxy(httpClient);
        return httpClient;
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
        final PostMethod request = new PostMethod(authInfo.getTokenUrl());
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            request.setParameter("grant_type", "refresh_token");
            request.setParameter("refresh_token", refreshToken);
        } else {
            // otherwise use the code
            request.setParameter("grant_type", "authorization_code");
            request.setParameter("code", authInfo.getParam("code"));
        }
        request.setParameter("redirect_uri", authInfo.getClientRedirectUri());
        request.setParameter("client_secret", authInfo.getClientSecret());
        request.setParameter("client_id", authInfo.getClientId());
        request.setRequestHeader(OAuth2Constants.HEADER_CONTENT_TYPE, "application/x-www-form-urlencoded");
        request.setRequestHeader(OAuth2Constants.HEADER_AUTHORIZATION, "Basic " + basicToken);
        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
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
     * @return The authorize uri
     */
    protected String buildAuthorizeUri(String template) {
        final String responseType = "code";
        String encodedRedirectUri = "";
        try {
            encodedRedirectUri = URLEncoder.encode(clientRedirectUri, OAuth2Constants.ENCODING);
        } catch (final UnsupportedEncodingException e) {
            ZimbraLog.extensions.errorQuietly("Invalid redirect URI found in client config.", e);
        }

        return String.format(template, clientId, encodedRedirectUri, responseType, scope);
    }

    /**
     * @see IOAuth2Handler#authorize(String)
     */
    public String authorize(String relayState) throws ServiceException {
        String relayValue = "";
        String relay = StringUtils.defaultString(relayState, "");

        if (!relay.isEmpty()) {
            try {
                relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING);
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to decode relay parameter.", e);
            }

            try {
                relayValue = "&" + relayKey + "="
                    + URLEncoder.encode(relay, OAuth2Constants.ENCODING);
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to encode relay parameter.", e);
            }
        }
        return authorizeUri + relayValue;
    }

    /**
     * @see IOAuth2Handler#authenticate(OAuthInfo)
     */
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        // set client specific properties
        oauthInfo.setClientId(clientId);
        oauthInfo.setClientSecret(clientSecret);
        oauthInfo.setClientRedirectUri(clientRedirectUri);
        oauthInfo.setTokenUrl(authenticateUri);
        // request credentials from social service
        final JsonNode credentials = getTokenRequest(oauthInfo, basicToken);
        // ensure the response contains the necessary credentials
        validateTokenResponse(credentials);
        // determine account associated with credentials
        final String username = getPrimaryEmail(credentials);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
        dataSource.syncDatasource(mailbox, oauthInfo);
        return true;
    }

    /**
     * Default getPrimaryEmail implementation. May be used by clients that
     * return an `id_token` in the get_token request - otherwise this method
     * must be overridden.<br>
     * Retrieves the social service account primary email from the `id_token`.
     *
     * @param credentials The get_token response containing an id_token
     * @return The primary email address associated with the credentials
     * @throws ServiceException If there are issues determining the primary
     *             address
     */
    protected String getPrimaryEmail(JsonNode credentials) throws ServiceException {
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
     * Default param verifier. Ensures no `error`, and that `code` is passed
     * in.<br>
     * This method should be overridden if the implementing client expects
     * different parameters.
     *
     * @see IOAuth2Handler#verifyAuthenticateParams()
     */
    public void verifyAuthenticateParams(Map<String, String> params) throws ServiceException {
        final String error = params.get("error");
        // check for errors
        if (!StringUtils.isEmpty(error)) {
            throw ServiceException.PERM_DENIED(error);
            // ensure code exists
        } else if (!params.containsKey("code")) {
            throw ServiceException.INVALID_REQUEST(OAuth2Constants.ERROR_INVALID_AUTH_CODE, null);
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
    public static JsonNode executeRequestForJson(HttpMethod request)
        throws ServiceException, IOException {
        JsonNode json = null;
        final String responseBody = executeRequest(request);

        // try to parse json
        // throw if the upstream response
        // is not what we previously expected
        try {
            json = mapper.readTree(responseBody);
        } catch (final JsonParseException e) {
            ZimbraLog.extensions.warn("The destination server responded with unexpected data.");
            throw ServiceException
                .PROXY_ERROR("The destination server responded with unexpected data.", null);
        }

        return json;
    }

    /**
     * Executes an Http Request and returns the response body.
     *
     * @param request Request to execute
     * @return Response body as a string
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    protected static String executeRequest(HttpMethod request)
        throws ServiceException, IOException {
        String responseBody = null;
        try {
            final HttpClient client = getHttpClient();
            HttpClientUtil.executeMethod(client, request);
            responseBody = request.getResponseBodyAsString();
        } catch (final UnknownHostException e) {
            ZimbraLog.extensions.errorQuietly(
                "The configured destination address is unknown: " + request.getURI(), e);
            throw ServiceException
                .RESOURCE_UNREACHABLE("The configured destination address is unknown.", e);
        } catch (final SocketTimeoutException e) {
            ZimbraLog.extensions
                .warn("The destination server took too long to respond to our request.");
            throw ServiceException.RESOURCE_UNREACHABLE(
                "The destination server took too long to respond to our request.", e);
        } catch (final ConnectionPoolTimeoutException e) {
            ZimbraLog.extensions
                .warn("Too many active HTTP client connections, not enough resources available.");
            throw ServiceException.TEMPORARILY_UNAVAILABLE();
        } finally {
            if (request != null) {
                request.releaseConnection();
            }
        }
        return responseBody;
    }

    /**
     * Retrieves the Zimbra mailbox via specified auth token.
     *
     * @param zmAuthToken The Zimbra auth token to identify the account with
     * @return The Zimbra mailbox
     * @throws ServiceException If there is an issue retrieving the account
     *             mailbox
     */
    protected ZMailbox getZimbraMailbox(String zmAuthToken) throws ServiceException {
        // create a mailbox by auth token
        try {
            return ZMailbox.getByAuthToken(new ZAuthToken(zmAuthToken), zimbraHostUri, true, true);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue acquiring the mailbox using the specified auth token.", e);
            throw e;
        }
    }

}
