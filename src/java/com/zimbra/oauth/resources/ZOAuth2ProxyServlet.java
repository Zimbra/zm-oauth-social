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
package com.zimbra.oauth.resources;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang.StringUtils;

import com.google.common.annotations.VisibleForTesting;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.zimlet.ProxyServlet;
import com.zimbra.oauth.models.HttpProxyServletRequest;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

/**
 * The ZOAuth2ProxyServlet class.<br>
 * Request entry point for the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.resources
 * @copyright Copyright © 2019
 */
public class ZOAuth2ProxyServlet extends ExtensionHttpHandler {

    /**
     * ProxyServlet to forward requests to.
     */
    protected final ProxyServlet proxyServlet;

    public ZOAuth2ProxyServlet() {
        this.proxyServlet = new ProxyServlet();
    }

    @VisibleForTesting
    public ZOAuth2ProxyServlet(ProxyServlet proxyServlet) {
        this.proxyServlet = proxyServlet;
    }

    @Override
    public String getPath() {
        return OAuth2Constants.PROXY_SERVER_PATH.getValue();
    }

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        doProxy(req, resp);
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        doProxy(req, resp);
    }

    @Override
    public void doPut(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        doProxy(req, resp);
    }

    @Override
    public void doDelete(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        doProxy(req, resp);
    }

    @Override
    public void doOptions(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        doProxy(req, resp);
    }

    protected void doProxy(HttpServletRequest req, HttpServletResponse resp)
        throws IOException, ServletException {
        final String path = StringUtils.removeEndIgnoreCase(req.getPathInfo(), "/");
        final Map<String, String> pathParams = parseRequestPath(path);

        // determine authorization + extra headers for client
        final ResponseObject<?> headersRes = OAuth2ResourceUtilities.headers(req.getMethod(),
            pathParams.get("client"), req.getCookies(), getHeaders(req), req.getParameterMap(),
            req.getInputStream());

        // handle errors if any
        if (Status.OK.getStatusCode() != headersRes.get_meta().getStatus()) {
            try {
                sendJsonResponse(resp, headersRes);
            } catch (final ServiceException e) {
                ZimbraLog.extensions.errorQuietly("Failed to send JSON error response before proxy.", e);
                resp.sendError(Status.INTERNAL_SERVER_ERROR.getStatusCode());
            }
            return;
        }

        // forward to proxy servlet
        proxyServlet.service(wrapWithHeaders(req, headersRes.getData()), resp);
    }

    /**
     * @param req The request to wrap
     * @param data Maybe extra headers to add
     * @return A wrapped http request (maybe with extra headers)
     */
    @SuppressWarnings("unchecked")
    protected HttpProxyServletRequest wrapWithHeaders(HttpServletRequest req, Object data) {
        final HttpProxyServletRequest reqWrapper = new HttpProxyServletRequest(req);
        if (data instanceof Map) {
            reqWrapper.setAll((Map<String, String>) data);
        }
        return reqWrapper;
    }

    /**
     * @param req The current request
     * @return A map of all request headers
     */
    private Map<String, String> getHeaders(HttpServletRequest req) {
        final Map<String, String> headers = new HashMap<String, String>();
        final Enumeration<String> requestHeaders = req.getHeaderNames();
        while (requestHeaders.hasMoreElements()) {
            final String name = requestHeaders.nextElement();
            headers.put(name, req.getHeader(name));
        }
        return headers;
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
        // client
        pathParams.put("client", parts[2]);
        return pathParams;
    }

    /**
     * Sends a response to the client based on the passed in ResponseObject.
     *
     * @param resp The output response
     * @param object The object to send with details
     * @throws IOException If there are issues writing out
     * @throws ServiceException If there are json issues
     */
    protected void sendJsonResponse(HttpServletResponse resp, ResponseObject<?> object)
        throws IOException, ServiceException {
        resp.setStatus(object.get_meta().getStatus());
        resp.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        resp.getWriter().print(OAuth2JsonUtilities.objectToJson(object));
        resp.flushBuffer();
    }

}
