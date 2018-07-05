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
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.lang.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zimbra.client.ZMailbox;
import com.zimbra.common.auth.ZAuthToken;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2DataSource;
import com.zimbra.oauth.utilities.OAuth2ErrorConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
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
     * @param client The app client name (yahoo, facebook, google, etc)
     * @param clientHost The hostname associated with the client
     */
    public OAuth2Handler(Configuration config, String client, String clientHost) {
        this.client = client;
        this.config = config;
        typeKey = OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue();
        dataSource = OAuth2DataSource.createDataSource(client, clientHost);
        final String zimbraHostname = config
            .getString(OAuth2ConfigConstants.LC_ZIMBRA_SERVER_HOSTNAME.getValue());
        // warn if missing hostname
        if (StringUtils.isEmpty(zimbraHostname)) {
            ZimbraLog.extensions.warn("The zimbra server hostname is not configured.");
        }
        // cache the host uri
        zimbraHostUri = String
            .format(config.getString(OAuth2ConfigConstants.LC_HOST_URI_TEMPLATE.getValue(),
                OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE.getValue()), zimbraHostname);
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
        request.setRequestHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setRequestHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
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
     * @return The authorize uri
     * @throws ServiceException If there are issues with the app configuration
     *             (missing credentials)
     */
    protected String buildAuthorizeUri(String template, Account account, String datasourceType) throws ServiceException {
        final String responseType = "code";
        String encodedRedirectUri = "";
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(), client), client,
            account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(), client),
            client, account);
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException
                .FAILURE("Required config(id, and redirectUri) parameters are not provided.", null);
        }

        final String scopeIdentifier = StringUtils.isEmpty(datasourceType)
            ? client
            : client + "_" + datasourceType;
        final String scope = StringUtils.join(new String[] { requiredScopes,
            config.getString(String.format(OAuth2ConfigConstants.LC_OAUTH_SCOPE_TEMPLATE.getValue(),
                client), scopeIdentifier, account) },
            scopeDelimiter);

        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.NOT_FOUND(String.format(
                "The app: %s is not properly configured, please set Oauth credentials and redirect uri",
                client), new Exception("Invalid config"));
        }

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
        final String relayState = params.get(relayKey);
        final String type = StringUtils.defaultString(params.get(typeKey), "");
        String relayValue = "";
        String relay = StringUtils.defaultString(relayState, "");

        if (!relay.isEmpty()) {
            try {
                relay = URLDecoder.decode(relay, OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to decode relay parameter.", e);
            }

            try {
                relayValue = "&" + relayKey + "="
                    + URLEncoder.encode(relay, OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to encode relay parameter.", e);
            }
        }

        if (!type.isEmpty()) {
            try {
                if (relayValue.isEmpty()) {
                    relayValue = "&" + relayKey + "=";
                }
                relayValue += RELAY_DELIMETER + URLEncoder.encode(type, OAuth2Constants.ENCODING.getValue());
            } catch (final UnsupportedEncodingException e) {
                throw ServiceException.INVALID_REQUEST("Unable to decode type parameter.", e);
            }
        } else {
            ZimbraLog.extensions.error("Missing data source type");
            throw ServiceException.FAILURE("Missing data source type", null);
        }

        return buildAuthorizeUri(authorizeUriTemplate, account, type) + relayValue;
    }

    /**
     * @see IOAuth2Handler#authenticate(OAuthInfo)
     */
    public Boolean authenticate(OAuthInfo oauthInfo) throws ServiceException {
        final Account account = oauthInfo.getAccount();
        final String clientId = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_ID_TEMPLATE.getValue(), client), client,
            account);
        final String clientSecret = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_SECRET_TEMPLATE.getValue(), client),
            client, account);
        final String clientRedirectUri = config.getString(
            String.format(OAuth2ConfigConstants.LC_OAUTH_CLIENT_REDIRECT_URI_TEMPLATE.getValue(), client),
            client, account);
        if (StringUtils.isEmpty(clientId) || StringUtils.isEmpty(clientSecret)
            || StringUtils.isEmpty(clientRedirectUri)) {
            throw ServiceException.FAILURE("Required config(id, secret and redirectUri) parameters are not provided.", null);
        }
        final String basicToken = OAuth2Utilities.encodeBasicHeader(clientId, clientSecret);
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
        final String username = getPrimaryEmail(credentials, account);
        ZimbraLog.extensions.trace("Authentication performed for:" + username);

        // get zimbra mailbox
        final ZMailbox mailbox = getZimbraMailbox(oauthInfo.getZmAuthToken());

        // store refreshToken
        oauthInfo.setUsername(username);
        oauthInfo.setRefreshToken(credentials.get("refresh_token").asText());
        dataSource.syncDatasource(mailbox, oauthInfo, getDatasourceCustomAttrs(oauthInfo));
        // add new datasource for calendar using oauth2calendar, if you want to use same
        // oauthinfo for calendar datasource. see example below
        // e.g. dataSource.syncDatasource(mailbox, oauthInfo, DataSourceType.oauth2calendar);
        return true;
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
        // code, error, state are default oauth2 keys
        return Arrays.asList(relayKey, typeKey);
    }

    /**
     * Default param verifier. Ensures no `error`, and that `code` is passed
     * in.<br>
     * This method should be overridden if the implementing client expects
     * different parameters.
     *
     * @see IOAuth2Handler#verifyAuthenticateParams()
     */
    public void verifyAndSplitAuthenticateParams(Map<String, String> params) throws ServiceException {
        // split available params before checking for errors
        if (params.containsKey(relayKey)) {
            final String[] origVal = params.get(relayKey).split(RELAY_DELIMETER);
            if (origVal.length != 2) {
                throw ServiceException.INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
            }
            params.put(relayKey, origVal[0]);
            if (origVal[1].isEmpty()) {
                throw ServiceException.INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
            } else {
                ZimbraLog.extensions.debug("Adding %s = %s", typeKey, origVal[1]);
                params.put(typeKey, origVal[1]);
            }
        } else {
            throw ServiceException.INVALID_REQUEST(OAuth2ErrorConstants.ERROR_TYPE_MISSING.getValue(), null);
        }

        final String error = params.get("error");
        // check for errors
        if (!StringUtils.isEmpty(error)) {
            throw ServiceException.PERM_DENIED(error);
            // ensure code exists
        } else if (!params.containsKey("code")) {
            throw ServiceException.INVALID_REQUEST(OAuth2ErrorConstants.ERROR_INVALID_AUTH_CODE.getValue(), null);
        }
    }

    /**
     * Default param verifier for authorize.
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
            OAuth2DataSource.getDataSourceTypeForOAuth2(type);
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
        final String responseBody = OAuth2Utilities.executeRequest(request);

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
