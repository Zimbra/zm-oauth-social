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
package com.zimbra.oauth.utilities;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URIBuilder;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.managers.ClassManager;
import com.zimbra.oauth.models.OAuthInfo;

/**
 * The OAuth2ResourceUtilities class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class OAuth2ResourceUtilities {

    /**
     * Handles client manager acquisition for authorize call.
     *
     * @param client The client
     * @param params Request params
     * @param account The user requesting
     * @return Location to redirect to
     * @acct the user account for which datasource is being setup
     * @throws ServiceException If there are issues
     */
    public static final String authorize(String client, Map<String, String[]> params, Account account)
            throws ServiceException {
        final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
        ZimbraLog.extensions.debug("Client : %s, handler:%s, relay:%s, type:%s ", client,
            oauth2Handler, params.get("relay"), params.get(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue()));
        final Map<String, String> paramsForAuthorize = getParams(
            oauth2Handler.getAuthorizeParamKeys(), params);
        oauth2Handler.verifyAuthorizeParams(paramsForAuthorize);
        return oauth2Handler.authorize(paramsForAuthorize, account);
    }

    /**
     * Handles client manager acquisition, and input organization for the
     * authenticate call.
     *
     * @param client The client
     * @param queryParams Map of query params
     * @param account The user requesting
     * @param zmAuthToken The Zimbra auth token
     * @return Location to redirect to
     * @throws ServiceException If there are issues
     */
    public static String authenticate(String client, Map<String, String[]> queryParams,
        Account account, String zmAuthToken) throws ServiceException {
        final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
        final Map<String, String> errorParams = new HashMap<String, String>();
        final Map<String, String> params = getParams(oauth2Handler.getAuthenticateParamKeys(),
            queryParams);

        // verify the expected params exist, with no errors
        try {
            oauth2Handler.verifyAndSplitAuthenticateParams(params);
        } catch (final ServiceException e) {
            if (StringUtils.equals(ServiceException.PERM_DENIED, e.getCode())) {
                // if unauthorized, pass along the error message
                errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(),
                    OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue());
                errorParams.put(OAuth2HttpConstants.QUERY_ERROR_MSG.getValue(), e.getMessage());
            } else {
                // if invalid op, pass along the error message
                errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(), e.getCode());
            }
        }

        if (errorParams.isEmpty()) {
            // if there is no zimbra auth code, the zimbra account cannot be
            // identified
            // this happens if the request has no zimbra cookie identifying a
            // session
            if (StringUtils.isEmpty(zmAuthToken)) {
                errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(),
                    OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE.getValue());
                errorParams.put(OAuth2HttpConstants.QUERY_ERROR_MSG.getValue(),
                    OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE_MSG.getValue());
            } else {
                try {
                    // no errors and auth token exists
                    // attempt to authenticate
                    final OAuthInfo authInfo = new OAuthInfo(params);
                    authInfo.setAccount(account);
                    authInfo.setZmAuthToken(zmAuthToken);
                    oauth2Handler.authenticate(authInfo);
                } catch (final ServiceException e) {
                    // unauthorized does not have an error message associated
                    // with it
                    if (StringUtils.equals(ServiceException.PERM_DENIED, e.getCode())) {
                        errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(),
                            OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue());
                    } else {
                        errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(),
                            OAuth2ErrorConstants.ERROR_AUTHENTICATION_ERROR.getValue());
                        errorParams.put(OAuth2HttpConstants.QUERY_ERROR_MSG.getValue(), e.getMessage());
                    }
                }
            }
        }

        // validate relay, then add error params if there are any, then redirect
        final String relay = oauth2Handler.getRelay(params);
        return addQueryParams(getValidatedRelay(relay), errorParams);
    }

    /**
     * Retrieves a map of query params expected for the client.
     *
     * @param expectedParams A list of params this client is looking for
     * @param queryParams Map of request query parameters
     * @return Map of params found
     */
    private static Map<String, String> getParams(List<String> expectedParams,
        Map<String, String[]> queryParams) {
        final Map<String, String> foundParams = new HashMap<String, String>(expectedParams.size());

        // check for every expected param, add if it exists
        for (final String key : expectedParams) {
            if (queryParams.containsKey(key)) {
                final String[] values = queryParams.get(key);
                if (values != null) {
                    foundParams.put(key, values[0]);
                }
            }
        }

        return foundParams;
    }

    /**
     * Returns a validated relative URI, or the default success redirect if no
     * valid url was provided.
     *
     * @param url The url to validate
     * @return relay A relative url
     */
    private static String getValidatedRelay(String url) {
        String relay = OAuth2Constants.DEFAULT_SUCCESS_REDIRECT.getValue();

        if (!StringUtils.isEmpty(url)) {
            try {
                // if the url can be decoded and is relative, then set it as our
                // relay
                final String decodedUrl = URLDecoder.decode(url,
                    OAuth2Constants.ENCODING.getValue());
                if (!new URI(decodedUrl).isAbsolute()) {
                    relay = decodedUrl;
                }
            } catch (final UnsupportedEncodingException e) {
                ZimbraLog.extensions.info("Unable to decode relay parameter.");
            } catch (final URISyntaxException e) {
                ZimbraLog.extensions.info("Invalid relay URI syntax found.");
            }
        }
        return relay;
    }

    /**
     * Add query parameters to a path.<br>
     * Empty path or param map results in no change.<br>
     * Empty key or value params are ignored.
     *
     * @param path The path to add to
     * @param params The params to add
     * @return The path with added query parameters, or the original path if we
     *         failed to add the params
     */
    public static String addQueryParams(String path, Map<String, String> params) {
        // do nothing for empty path, or param map
        if (StringUtils.isEmpty(path) || params == null || params.size() < 1) {
            return path;
        }

        try {
            final URIBuilder pathUri = new URIBuilder(path);
            // add each param if the key and value are not empty
            for (final Entry<String, String> param : params.entrySet()) {
                final String key = param.getKey();
                final String value = param.getValue();
                if (!StringUtils.isEmpty(key) && !StringUtils.isEmpty(value)) {
                    pathUri.addParameter(key, value);
                }
            }
            return pathUri.build().toString();
        } catch (final URISyntaxException e) {
            ZimbraLog.extensions
                .warn("There was an issue adding query parameters to the path: " + path);
        }
        // return the original path without the added params if we failed
        return path;
    }

}
