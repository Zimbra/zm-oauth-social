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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.http.conn.ConnectionPoolTimeoutException;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.httpclient.HttpProxyUtil;
import com.zimbra.cs.mailbox.Contact.Attachment;
import com.zimbra.oauth.models.ResponseObject;

/**
 * The OAuth2Utilities class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class OAuth2Utilities {

    /**
     * Creates a mapper that can convert between Java <-> JSON objects.
     *
     * @return mapper A mapper object
     */
    public static ObjectMapper createDefaultMapper() {
        final ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_CONTROL_CHARS, true);
        return mapper;
    }

    /**
     * Creates a Basic authorization header.
     *
     * @param user The left param
     * @param pass The right param
     * @return Basic authorization header
     */
    public static String encodeBasicHeader(String user, String pass) {
        return Base64.getEncoder().encodeToString(new String(user + ":" + pass).getBytes());
    }

    /**
     * Builds an HTTP response object.
     *
     * @param entity Model to display
     * @param status HTTP Status
     * @param headers HTTP Headers
     * @return HTTP response object
     */
    public static Response buildResponse(ResponseObject<? extends Object> entity, Status status,
        Map<String, Object> headers) {
        // status
        if (status == null) {
            status = Status.OK;
        }
        final ResponseBuilder resBuilder = Response.status(status);
        // body
        if (entity != null) {
            resBuilder.entity(entity);
        }
        // headers
        if (headers != null && !headers.isEmpty()) {
            for (final Entry<String, Object> entry : headers.entrySet()) {
                resBuilder.header(entry.getKey(), entry.getValue());
            }
        }
        return resBuilder.build();
    }

    /**
     * Decodes given stream with a size boundary.
     *
     * @param input An InputStream object
     * @param size A boundary limit (optional : Use 0 to default)
     * @return The the current contents of this output stream, as a byte array.
     * @throws IOException
     */
    public static byte[] decodeStream(InputStream input, long size) throws IOException {
        final long MIN_BUFFER_SIZE = 100;
        final long MAX_BUFFER_SIZE = 4096;
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int lengthRead;
        // buffer size must be within our bounds
        if (size < MIN_BUFFER_SIZE || size > MAX_BUFFER_SIZE) {
            size = MAX_BUFFER_SIZE;
        }
        final byte[] data = new byte[(int) size];
        try {
            // read until the end
            while ((lengthRead = input.read(data)) != -1) {
                buffer.write(data, 0, lengthRead);
            }
            buffer.flush();
        } finally {
            // always close the input
            input.close();
        }
        return buffer.toByteArray();
    }

    /**
     * Creates an image Attachment object from a get response given a field key and filename.
     *
     * @param method The http response
     * @param key The field key
     * @param filename The name for the file
     * @return An image Attachment object
     * @throws IOException If there are issues creating the attachment with the given parameters
     */
    public static Attachment createAttachmentFromResponse(GetMethod method, String key,
        String filename) throws IOException {
        // check for the content type header
        final Header ctypeHeader = method.getResponseHeader("Content-Type");
        if (ctypeHeader != null) {
            // grab content type header as string
            final String ctype = StringUtils.lowerCase(ctypeHeader.getValue());
            ZimbraLog.extensions.debug("The Content-Type: %s", ctype);
            if (StringUtils.startsWith(ctype, "image/")) {
                ZimbraLog.extensions.debug("Creating image attachment: %s as key: %s", filename, key);
                return new Attachment(
                    decodeStream(method.getResponseBodyAsStream(),
                        Integer.valueOf(OAuth2Constants.CONTACTS_IMAGE_BUFFER_SIZE.getValue())),
                    ctype, key, filename);
            }
        }
        return null;
    }

    /**
     * Executes an Http Request and returns the response body.
     *
     * @param request Request to execute
     * @return Response body as a string
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static String executeRequest(HttpMethod request)
        throws ServiceException, IOException {
        final HttpClient client = OAuth2Utilities.getHttpClient();
        return executeRequest(client, request);
    }

    /**
     * Executes an Http Request with a given client and returns the response body.
     *
     * @param client The client to execute with
     * @param request Request to execute
     * @return Response body as a string
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static String executeRequest(HttpClient client, HttpMethod request)
        throws ServiceException, IOException {
        String responseBody = null;
        try {
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
     * Get an instance of HttpClient which is configured to use Zimbra proxy.
     *
     * @return HttpClient A HttpClient instance
     */
    public static HttpClient getHttpClient() {
        final HttpClient httpClient = ZimbraHttpConnectionManager.getExternalHttpConnMgr()
            .newHttpClient();
        HttpProxyUtil.configureProxy(httpClient);
        return httpClient;
    }
}
