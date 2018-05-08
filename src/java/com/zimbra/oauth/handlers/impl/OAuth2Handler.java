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
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ConnectionPoolTimeoutException;

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
import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.exceptions.InvalidOperationException;
import com.zimbra.oauth.exceptions.InvalidResponseException;
import com.zimbra.oauth.exceptions.ServiceNotAvailableException;
import com.zimbra.oauth.exceptions.UnreachableHostException;
import com.zimbra.oauth.exceptions.UserUnauthorizedException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The OAuth2Handler class.<br>
 * Base OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class OAuth2Handler {

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
    public OAuth2Handler(Configuration config) {
        this.config = config;
        synchronized (OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME) {
            final String zimbraHostname = config
                .getString(OAuth2Constants.LC_ZIMBRA_SERVER_HOSTNAME);
            // warn if missing hostname
            if (StringUtils.isEmpty(zimbraHostname)) {
                ZimbraLog.extensions.warn("The zimbra server hostname is not configured.");
            }
            // cache the host uri
            zimbraHostUri = String.format(config.getString(OAuth2Constants.LC_HOST_URI_TEMPLATE,
                OAuth2Constants.DEFAULT_HOST_URI_TEMPLATE), zimbraHostname);
        }
    }

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
     * Declares the query params to look for on oauth2 authenticate
     * callback.<br>
     * This method should be overriden if the implementing client uses different
     * parameters.
     *
     * @see IOAuth2Handler#getAuthenticateParamKeys()
     */
    public List<String> getAuthenticateParamKeys() {
        // code, error, state are default oauth2 keys
        return Arrays.asList("code", "error", "state");
    }

    /**
     * Default param verifier. Ensures no `error`, and that `code` is passed
     * in.<br>
     * This method should be overriden if the implementing client expects
     * different parameters.
     *
     * @see IOAuth2Handler#verifyAuthenticateParams()
     */
    public void verifyAuthenticateParams(Map<String, String> params) throws GenericOAuthException {
        final String error = params.get("error");
        // check for errors
        if (!StringUtils.isEmpty(error)) {
            throw new UserUnauthorizedException(error);
            // ensure code exists
        } else if (!params.containsKey("code")) {
            throw new InvalidOperationException(OAuth2Constants.ERROR_INVALID_AUTH_CODE);
        }
    }

    /**
     * Returns the relay state param for the client.<br>
     * This method should be overriden if the implementing client uses a
     * different key for relay.
     *
     * @see IOAuth2Handler#getRelay()
     */
    public String getRelay(Map<String, String> params) {
        return params.get("state");
    }

    /**
     * Executes an Http Request and parses for json.
     *
     * @param request Request to execute
     * @return Json response
     * @throws GenericOAuthException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    protected JsonNode executeRequestForJson(HttpMethod request)
        throws GenericOAuthException, IOException {
        JsonNode json = null;
        final String responseBody = executeRequest(request);

        // try to parse json
        // throw if the upstream response
        // is not what we previously expected
        try {
            json = mapper.readTree(responseBody);
        } catch (final JsonParseException e) {
            ZimbraLog.extensions.warn("The destination server responded with unexpected data.");
            throw new InvalidResponseException(
                "The destination server responded with unexpected data.");
        }

        return json;
    }

    /**
     * Executes an Http Request and returns the response body.
     *
     * @param request Request to execute
     * @return Response body as a string
     * @throws GenericOAuthException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    protected String executeRequest(HttpMethod request) throws GenericOAuthException, IOException {
        String responseBody = null;
        try {
            final HttpClient client = getHttpClient();
            HttpClientUtil.executeMethod(client, request);
            responseBody = request.getResponseBodyAsString();
        } catch (final UnknownHostException e) {
            ZimbraLog.extensions
                .errorQuietly("The configured destination address is unknown: " + request.getURI(), e);
            throw new UnreachableHostException("The configured destination address is unknown.");
        } catch (final SocketTimeoutException e) {
            ZimbraLog.extensions
                .warn("The destination server took too long to respond to our request.");
            throw new UnreachableHostException(
                "The destination server took too long to respond to our request.");
        } catch (final ConnectionPoolTimeoutException e) {
            ZimbraLog.extensions.warn(
                "Too many active HTTP client connections, not enough resources available.");
            throw new ServiceNotAvailableException(
                "Too many active connections, not enough resources available.");
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
     * @throws UserUnauthorizedException If there is an issue retrieving the
     *             account mailbox
     */
    protected ZMailbox getZimbraMailbox(String zmAuthToken) throws UserUnauthorizedException {
        // create a mailbox by auth token
        try {
            return ZMailbox.getByAuthToken(new ZAuthToken(zmAuthToken), zimbraHostUri, true, true);
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly(
                "There was an issue acquiring the mailbox using the specified auth token.", e);
            throw new UserUnauthorizedException(
                "There was an issue acquiring the mailbox using the specified auth token", e);
        }
    }

}
