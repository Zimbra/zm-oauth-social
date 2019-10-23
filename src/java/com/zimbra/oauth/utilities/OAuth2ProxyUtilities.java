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
package com.zimbra.oauth.utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;

import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClientBuilder;

import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ByteUtil;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Cos;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.httpclient.HttpProxyUtil;
import com.zimbra.oauth.models.ErrorMessage;
import com.zimbra.oauth.models.ResponseMeta;
import com.zimbra.oauth.models.ResponseObject;

/**
 * The OAuth2ProxyUtilities class.<br>
 * Based on the ProxyServlet class, without the FileUpload functionality.<br>
 * Note: This class does not use the usual OAuth2Utilities Http methods.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2019
 * @see com.zimbra.cs.zimlet.ProxyServlet
 */
public class OAuth2ProxyUtilities {

    private static final String TARGET_PARAM = "target";

    private static final String USER_PARAM = "user";
    private static final String PASS_PARAM = "pass";
    private static final String AUTH_PARAM = "auth";
    private static final String AUTH_BASIC = "basic";
    private static final String DEFAULT_CTYPE = "text/xml";

    protected static Set<String> getAllowedDomains(Account account) throws ServiceException {
        final Provisioning prov = Provisioning.getInstance();

        final Cos cos = prov.getCOS(account);

        final Set<String> allowedDomains = cos.getMultiAttrSet(Provisioning.A_zimbraProxyAllowedDomains);

        ZimbraLog.extensions.debug("get allowedDomains result: " + allowedDomains);

        return allowedDomains;
    }

    public static boolean isAllowedTargetHost(String host, Account account) {
        if (StringUtils.isEmpty(host)) {
            return false;
        }
        ZimbraLog.extensions.debug("checking allowedDomains permission on target host: " + host);
        Set<String> domains;
        try {
            domains = getAllowedDomains(account);
        } catch (final ServiceException se) {
            ZimbraLog.extensions.info("error getting allowedDomains: " + se.getMessage());
            return false;
        }
        for (String domain : domains) {
            if (domain.equals("*")) {
                return true;
            }
            if (domain.charAt(0) == '*') {
                domain = domain.substring(1);
            }
            if (host.endsWith(domain)) {
                return true;
            }
        }
        return false;
    }

    protected static boolean canProxyHeader(String header) {
        if (header == null) {
            return false;
        }
        header = header.toLowerCase();
        return !(header.startsWith("accept")
            || header.equals("content-length")
            || header.equals("connection")
            || header.equals("keep-alive")
            || header.equals("pragma")
            || header.equals("host")
            || header.equals("cache-control")
            || header.equals("cookie")
            || header.equals("origin")
            || header.equals("transfer-encoding"));
    }

    protected static byte[] copyPostedData(HttpServletRequest req) throws IOException {
        int size = req.getContentLength();
        if (req.getMethod().equalsIgnoreCase("GET") || size <= 0) {
            return null;
        }
        final InputStream is = req.getInputStream();
        ByteArrayOutputStream baos = null;
        try {
            if (size < 0) {
                size = 0;
            }
            baos = new ByteArrayOutputStream(size);
            final byte[] buffer = new byte[8192];
            int num;
            while ((num = is.read(buffer)) != -1) {
                baos.write(buffer, 0, num);
            }
            return baos.toByteArray();
        } finally {
            ByteUtil.closeStream(baos);
        }
    }

    protected static void sendError(HttpServletResponse resp, int statusCode, String code) throws IOException {
        resp.setStatus(statusCode);
        resp.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        try {
            resp.getWriter().print(OAuth2JsonUtilities.objectToJson(new ResponseObject<ErrorMessage>(
                new ErrorMessage(code),
                new ResponseMeta(statusCode))));
            resp.flushBuffer();
        } catch (final ServiceException e) {
            ZimbraLog.extensions.errorQuietly("Failed to write proxy error response.", e);
        }
    }

    public static void doProxy(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        // get the posted body before the server read and parse them.
        final byte[] body = copyPostedData(req);

        final String target = req.getParameter(TARGET_PARAM);
        if (target == null) {
            sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
                OAuth2ErrorConstants.ERROR_PARAM_MISSING.getValue());
            return;
        }

        HttpRequestBase method = null;
        try {
            final HttpClientBuilder clientBuilder = ZimbraHttpConnectionManager.getExternalHttpConnMgr()
                .newHttpClient();
            HttpProxyUtil.configureProxy(clientBuilder);
            final String reqMethod = req.getMethod();
            if (reqMethod.equalsIgnoreCase("GET")) {
                method = new HttpGet(target);
            } else if (reqMethod.equalsIgnoreCase("POST")) {
                final HttpPost post = new HttpPost(target);
                if (body != null) {
                    post.setEntity(
                        new ByteArrayEntity(body, ContentType.create(req.getContentType())));
                }
                method = post;
            } else if (reqMethod.equalsIgnoreCase("PUT")) {
                final HttpPut put = new HttpPut(target);
                if (body != null) {
                    put.setEntity(
                        new ByteArrayEntity(body, ContentType.create(req.getContentType())));
                }
                method = put;
            } else if (reqMethod.equalsIgnoreCase("DELETE")) {
                method = new HttpDelete(target);
            } else {
                ZimbraLog.extensions.info("unsupported request method: " + reqMethod);
                sendError(resp, HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    OAuth2ErrorConstants.ERROR_INVALID_PROXY_TARGET.getValue());
                return;
            }

            // handle basic auth
            String auth, user, pass;
            auth = req.getParameter(AUTH_PARAM);
            user = req.getParameter(USER_PARAM);
            pass = req.getParameter(PASS_PARAM);
            if (auth != null && user != null && pass != null) {
                if (!auth.equals(AUTH_BASIC)) {
                    ZimbraLog.extensions.info("unsupported auth type: " + auth);
                    sendError(resp, HttpServletResponse.SC_BAD_REQUEST,
                        OAuth2ErrorConstants.ERROR_INVALID_AUTH_CODE.getValue());
                    return;
                }
                final CredentialsProvider provider = new BasicCredentialsProvider();
                provider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(user, pass));
                clientBuilder.setDefaultCredentialsProvider(provider);
            }

            final Enumeration<String> headers = req.getHeaderNames();
            while (headers.hasMoreElements()) {
                final String hdr = headers.nextElement();
                ZimbraLog.extensions.debug("incoming: " + hdr + ": " + req.getHeader(hdr));
                if (canProxyHeader(hdr)) {
                    ZimbraLog.extensions.debug("outgoing: " + hdr + ": " + req.getHeader(hdr));
                    if (hdr.equalsIgnoreCase("x-host")) {
                        method.setHeader("Host", req.getHeader(hdr));
                    } else {
                        method.addHeader(hdr, req.getHeader(hdr));
                    }
                }
            }

            HttpResponse httpResp = null;
            try {
                if (!(reqMethod.equalsIgnoreCase("POST") || reqMethod.equalsIgnoreCase("PUT"))) {
                    clientBuilder.setRedirectStrategy(new DefaultRedirectStrategy());
                }
                final HttpClient client = clientBuilder.build();
                httpResp = HttpClientUtil.executeMethod(client, method);
            } catch (final HttpException ex) {
                ZimbraLog.extensions.info("exception while proxying " + target, ex);
                sendError(resp, HttpServletResponse.SC_NOT_FOUND,
                    OAuth2ErrorConstants.ERROR_INVALID_PROXY_RESPONSE.getValue());
                return;
            }

            final int status = httpResp.getStatusLine() == null
                ? HttpServletResponse.SC_INTERNAL_SERVER_ERROR
                : httpResp.getStatusLine().getStatusCode();

            // workaround for Alexa Thumbnails paid web service, which doesn't
            // bother to return a content-type line
            final Header ctHeader = httpResp.getFirstHeader("Content-Type");
            final String contentType = ctHeader == null || ctHeader.getValue() == null ? DEFAULT_CTYPE
                : ctHeader.getValue();

            // getEntity may return null if no response body (e.g. HTTP 204)
            InputStream targetResponseBody = null;
            final HttpEntity targetResponseEntity = httpResp.getEntity();
            if (targetResponseEntity != null) {
                targetResponseBody = targetResponseEntity.getContent();
            }

            resp.setStatus(status);
            resp.setContentType(contentType);
            for (final Header h : httpResp.getAllHeaders())
                if (canProxyHeader(h.getName())) {
                    resp.addHeader(h.getName(), h.getValue());
                }
            if (targetResponseBody != null) {
                ByteUtil.copy(targetResponseBody, true, resp.getOutputStream(), true);
            }
        } finally {
            if (method != null)
                method.releaseConnection();
        }
    }

}
