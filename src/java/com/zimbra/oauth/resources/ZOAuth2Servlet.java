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
package com.zimbra.oauth.resources;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang.StringUtils;

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
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

/**
 * The ZOAuth2Servlet class.<br>
 * Request entry point for the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.resources
 * @copyright Copyright © 2018
 */
public class ZOAuth2Servlet extends ExtensionHttpHandler {

    @Override
    public String getPath() {
        return OAuth2Constants.DEFAULT_SERVER_PATH;
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        final String path = StringUtils.removeEndIgnoreCase(req.getPathInfo(), "/");
        if (!isValidPath(path)) {
            // invalid location - not part of this service
            resp.sendError(Status.BAD_REQUEST.getStatusCode());
            return;
        }
        final Map<String, String> pathParams = parseRequestPath(path);
        final String client = pathParams.get("client");
        String location = OAuth2Constants.DEFAULT_SUCCESS_REDIRECT;

        String encodeAuthToken = getEncodedAuthTokenFromCookie(req);
        Account account = getAccount(req, encodeAuthToken);
        ZimbraLog.extensions.debug("Account is:%s", account);

        if (account == null) {
            throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
                + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
        }
        try {
            switch (pathParams.get("action")) {
            case "authorize":
                location = OAuth2ResourceUtilities.authorize(client, req.getParameter("relay"), account);
                break;
            case "authenticate":
                location = OAuth2ResourceUtilities.authenticate(client, req.getParameterMap(),
                    account, encodeAuthToken);
                break;
            default:
                // missing valid action - bad request
                resp.sendError(Status.BAD_REQUEST.getStatusCode());
                return;
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("An unhandled oauth application error occurred.", e);
            final Map<String, String> errorParams = new HashMap<String, String>();
            errorParams.put(OAuth2Constants.QUERY_ERROR,
                OAuth2Constants.ERROR_UNHANDLED_ERROR);
            resp.sendRedirect(OAuth2ResourceUtilities.addQueryParams(
                OAuth2Constants.DEFAULT_SUCCESS_REDIRECT, errorParams));
            return;
        }
        ZimbraLog.extensions.debug("Authorization URI:%s", location);
        // set response redirect location
        resp.sendRedirect(location);
    }

    /**
     * Determines if the path is one serviced by this extension.
     *
     * @param path The path to check
     * @return True if the op is serviceable
     */
    protected boolean isValidPath(String path) {
        return StringUtils.containsIgnoreCase(path, "authenticate/")
            || StringUtils.containsIgnoreCase(path, "authorize/");
    }

    /**
     * Retrieves the zm auth token from the request.
     *
     * @param cookies The request cookies
     * @return The zm auth token
     */
    protected String getAuthToken(Cookie[] cookies) {
        for (final Cookie cookie : cookies) {
            if (StringUtils.equals(cookie.getName(), OAuth2Constants.COOKIE_AUTH_TOKEN)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Parses the path for the request path parameters.
     *
     * @param path The path to parse
     * @return Path parameters
     */
    protected Map<String, String> parseRequestPath(String path) {
        final Map<String, String> pathParams = new HashMap<String, String>();
        final String[] parts = path.split("/");
        // action
        if (StringUtils.equalsIgnoreCase(parts[2], "authorize")
            || StringUtils.equalsIgnoreCase(parts[2], "authenticate")) {
            pathParams.put("action", parts[2]);
        }
        // client
        if (StringUtils.isNotEmpty(parts[3])) {
            pathParams.put("client", parts[3]);
        }
        return pathParams;
    }
    private Account getAccount(HttpServletRequest req, String encodeAuthToken) throws ServletException {

       Account account = null;
        try {
            AuthToken authToken = ZimbraAuthToken.getAuthToken(encodeAuthToken);

            if (authToken != null) {

                if (authToken.isZimbraUser()) {
                    if(!authToken.isRegistered()) {
                        throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
                              + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
                    }
                    try {
                        account = AuthProvider.validateAuthToken(Provisioning.getInstance(), authToken, false);
                    } catch (ServiceException e) {
                        throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
                              + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
                    }
                } else {
                    throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
                        + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
                }
            } else {
                throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
                    + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
            }

        } catch (AuthTokenException e) {
            ZimbraLog.extensions.info("Error authenticating user.");
            throw new ServletException(HttpServletResponse.SC_UNAUTHORIZED
               + ": " + L10nUtil.getMessage(MsgKey.errMustAuthenticate, req));
        }

        return account;
      
    }
    private String getEncodedAuthTokenFromCookie(HttpServletRequest req) {
        String cookieName = ZimbraCookie.authTokenCookieName(false);
        String encodedAuthToken = null;
        javax.servlet.http.Cookie cookies[] =  req.getCookies();
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
