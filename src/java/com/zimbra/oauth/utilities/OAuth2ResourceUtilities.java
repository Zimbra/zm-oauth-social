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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.utils.URIBuilder;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.L10nUtil;
import com.zimbra.common.util.L10nUtil.MsgKey;
import com.zimbra.common.util.ZimbraCookie;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.AuthTokenException;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.ZimbraAuthToken;
import com.zimbra.cs.account.ZimbraJWToken;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.cs.service.util.JWTUtil;
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
     * @param cookies Request cookies
     * @param headers Request headers required for authorize
     * @param params Request params
     * @return Location to redirect to
     * @throws ServiceException If there are issues
     */
    public static final String authorize(String client, Cookie[] cookies,
        Map<String, String> headers, Map<String, String[]> params)
            throws ServiceException {
        // search for credentials
        final AuthToken authToken = getAuthToken(cookies, headers);
        // get account first to auth the user
        final Account account = getAccount(authToken);
        // get handler next to validate the client
        final IOAuth2Handler oauth2Handler = ClassManager.getHandler(client);
        ZimbraLog.extensions.debug("Client : %s, handler:%s, state:%s, type:%s ", client,
            oauth2Handler, params.get("state"),
            params.get(OAuth2HttpConstants.OAUTH2_TYPE_KEY.getValue()));
        final Map<String, String> paramsForAuthorize = getParams(
            oauth2Handler.getAuthorizeParamKeys(), params);
        try {
            // verify params
            oauth2Handler.verifyAuthorizeParams(paramsForAuthorize);
            if (isJWT(authToken)) {
                // if our credential is a jwt, pass it along too
                paramsForAuthorize.put(OAuth2HttpConstants.JWT_PARAM_KEY.getValue(),
                    authToken.getEncoded());
            }
            return oauth2Handler.authorize(paramsForAuthorize, account);
        } catch (final ServiceException e) {
            // return redirect error if invalid request
            if (ServiceException.INVALID_REQUEST.equals(e.getCode())) {
                return OAuth2ResourceUtilities.addQueryParams(
                    getValidatedRelay(oauth2Handler.getRelay(paramsForAuthorize)),
                    mapError(OAuth2ErrorConstants.ERROR_PARAM_MISSING.getValue(), e.getMessage()));
            }
            // otherwise bubble error
            throw e;
        } catch (final AuthTokenException e) {
            throw ServiceException
                .PERM_DENIED(OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE.getValue());
        }
    }

    /**
     * Handles client manager acquisition, and input organization for the
     * authenticate call.
     *
     * @param client The client
     * @param cookies Request cookies
     * @param headers Request headers required for authenticate
     * @param queryParams Map of query params
     * @return Location to redirect to
     * @throws ServiceException If there are issues
     */
    public static String authenticate(String client, Cookie[] cookies, Map<String, String> headers,
        Map<String, String[]> queryParams) throws ServiceException {
        // don't check for auth credentials until we can
        // check the client's state param for a jwt
        // get handler to validate the client
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
                mapError(errorParams, OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue(),
                    e.getMessage());
            } else {
                // if invalid op, pass along the error message
                mapError(errorParams, e.getCode(), null);
            }
        }

        // search for credentials
        final AuthToken authToken = getAuthToken(cookies, headers,
            params.get(OAuth2HttpConstants.JWT_PARAM_KEY.getValue()));
        if (authToken == null) {
            // if there is no zimbra session, the zimbra account cannot be identified
            mapError(errorParams, OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE.getValue(),
                OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE_MSG.getValue());
        }

        // get account to auth the user
        final Account account = getAccount(authToken);

        if (errorParams.isEmpty()) {
            try {
                // no errors and authToken exists
                // attempt to authenticate
                final OAuthInfo authInfo = new OAuthInfo(params);
                authInfo.setAccount(account);
                authInfo.setZmAuthToken(authToken);
                oauth2Handler.authenticate(authInfo);
            } catch (final ServiceException e) {
                // unauthorized does not have an error message associated
                // with it
                if (StringUtils.equals(ServiceException.PERM_DENIED, e.getCode())) {
                    mapError(errorParams, OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue(),
                        null);
                } else {
                    mapError(errorParams,
                        OAuth2ErrorConstants.ERROR_AUTHENTICATION_ERROR.getValue(),
                        e.getMessage());
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
    protected static Map<String, String> getParams(List<String> expectedParams,
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

    /**
     * Creates a query error map for a given code and message.
     *
     * @param code The error code
     * @param message The error message (optional)
     * @return Error map
     */
    public static Map<String, String> mapError(String code, String message) {
        return mapError(new HashMap<String, String>(), code, message);
    }

    /**
     * Creates a query error map for a given code and message.
     *
     * @param errorParams The map to add to
     * @param code The error code
     * @param message The error message (optional)
     * @return Error map
     */
    public static Map<String, String> mapError(Map<String, String> errorParams, String code, String message) {
        errorParams.put(OAuth2HttpConstants.QUERY_ERROR.getValue(), code);
        if (message != null) {
            errorParams.put(OAuth2HttpConstants.QUERY_ERROR_MSG.getValue(), message);
        }
        return errorParams;
    }

    /**
     * Wraps JWTUtil.isJWT to simplify test mock.
     *
     * @param token The token in question
     * @return True if the token is a jwt
     */
    protected static boolean isJWT(AuthToken token) {
        return JWTUtil.isJWT(token);
    }

    /**
     * Retrieves authToken with jwt from state param as priority.<br>
     * If no jwt from state param exists, forwards to default cookie/header check.
     *
     * @param cookies Request cookies
     * @param headers Request headers
     * @param string JWT from client's state param
     * @return An auth token
     * @throws ServiceException If there are issues creating the auth token
     */
    protected static AuthToken getAuthToken(Cookie[] cookies, Map<String, String> headers, String jwt)
        throws ServiceException {
        AuthToken authToken = null;
        if (!StringUtils.isEmpty(jwt)) {
            try {
                jwt = URLDecoder.decode(jwt, OAuth2Constants.ENCODING.getValue());
                final String salt = getFromCookie(cookies, ZimbraCookie.COOKIE_ZM_JWT);
                authToken = ZimbraJWToken.getJWToken(jwt, salt);
                ZimbraLog.extensions.debug("Using jwt from state param for auth token.");
            } catch (final AuthTokenException | UnsupportedEncodingException e) {
                ZimbraLog.extensions.debug("Unable to validate JWT.");
                throw ServiceException.PERM_DENIED("Unable to validate JWT.");
            }
        } else {
            // no jwt in state param, check headers and cookies
            authToken = getAuthToken(cookies, headers);
        }
        return authToken;
    }

    /**
     * Retrieves authToken from header or cookie.<br>
     * JWT is searched for as priority, then cookie.
     *
     * @param cookies Request cookies
     * @param headers Request headers
     * @return An auth token
     * @throws ServiceException If there are issues creating the auth token
     */
    protected static AuthToken getAuthToken(Cookie[] cookies, Map<String, String> headers)
        throws ServiceException {
        AuthToken authToken = null;
        // search for JWT auth first (priority)
        final String salt = getFromCookie(cookies, ZimbraCookie.COOKIE_ZM_JWT);
        final String jwtString = headers.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue());
        try {
            if (!StringUtils.isEmpty(jwtString) && !StringUtils.isEmpty(salt)) {
                authToken = ZimbraJWToken
                    .getJWToken(StringUtils.substringAfter(jwtString, "Bearer "), salt);
            }
            if (authToken == null) {
                // if we couldn't find a JWT, search for cookie auth
                final String cookieString = getFromCookie(cookies,
                    ZimbraCookie.authTokenCookieName(false));
                if (!StringUtils.isEmpty(cookieString)) {
                    authToken = ZimbraAuthToken.getAuthToken(cookieString);
                }

            }
        } catch (final AuthTokenException e) {
            ZimbraLog.extensions.info("Error authenticating user.");
            throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
        }
        return authToken;
    }

    /**
     * Returns the requesting user's account.<br>
     * Throws an exception if an account cannot be retrieved.
     *
     * @param authToken The auth token to retrieve the account with
     * @return The requesting user's account
     * @throws ServiceException If there are issues retrieving the account
     */
    protected static Account getAccount(AuthToken authToken) throws ServiceException {
        Account account = null;
        if (authToken != null) {
            if (authToken.isZimbraUser()) {
                if (!authToken.isRegistered()) {
                    throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                        + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
                }
                try {
                    account = AuthProvider.validateAuthToken(Provisioning.getInstance(),
                        authToken, false);
                } catch (final ServiceException e) {
                    throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                        + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
                }
            } else {
                throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                    + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
            }
        } else {
            throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
        }

        if (account == null) {
            throw ServiceException.PERM_DENIED(HttpServletResponse.SC_UNAUTHORIZED + ": "
                + L10nUtil.getMessage(MsgKey.errMustAuthenticate));
        }

        ZimbraLog.extensions.debug("Account is:%s", account);

        return account;
    }

    /**
     * Retrieves a cookie from the cookie jar.
     *
     * @param cookies Cookie jar
     * @param cookieName The specific cookie we need
     * @return A cookie
     */
    private static String getFromCookie(Cookie [] cookies, String cookieName) {
        String encodedAuthToken = null;
        if (cookies != null) {
            for (int i = 0; i < cookies.length; i++) {
                if (cookies[i].getName().equals(cookieName)) {
                    encodedAuthToken = cookies[i].getValue();
                    break;
                }
            }
        }
        return encodedAuthToken;
    }

}
