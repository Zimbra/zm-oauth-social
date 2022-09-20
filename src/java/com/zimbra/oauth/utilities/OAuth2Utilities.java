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

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.httpclient.HttpProxyUtil;
import com.zimbra.cs.mailbox.Contact.Attachment;
import com.zimbra.oauth.models.HttpResponseWrapper;
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
        return encodeString(new String(user + ":" + pass));
    }

    /**
     * Encodes the specified string.
     *
     * @param string String to encode
     * @return Base64-encoded string
     */
    public static String encodeString(String string) {
        return Base64.getEncoder().encodeToString(string.getBytes());
    }

    /**
     * Decodes the specified string.
     *
     * @param string Base64 string to decode
     * @return Decoded string
     */
    public static String decodeString(String string) {
        return new String(Base64.getDecoder().decode(string.getBytes()));
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
     * Decodes given http entity.<br>
     * Returns null if the entity is null.
     *
     * @param entity An http entity
     * @return The the current contents of this output stream, as a byte array.
     * @throws IOException If there are issues decoding
     */
    protected static byte[] decodeEntity(HttpEntity entity) throws IOException {
        byte[] entityBytes = null;
        if (entity != null) {
            entityBytes = EntityUtils.toByteArray(entity);
        }
        return entityBytes;
    }

    /**
     * Creates an image Attachment object from a get response given a field key and filename.
     *
     * @param response The http response
     * @param key The field key
     * @param filename The name for the file
     * @return An image Attachment object
     * @throws IOException If there are issues creating the attachment with the given parameters
     */
    public static Attachment createAttachmentFromResponse(HttpResponseWrapper responseWrapper, String key,
        String filename) throws IOException {
        // check for the content type header
        final HttpResponse response = responseWrapper.getResponse();
        final Header ctypeHeader = response.getFirstHeader("Content-Type");
        if (ctypeHeader != null) {
            // grab content type header as string
            final String ctype = StringUtils.lowerCase(ctypeHeader.getValue());
            final byte[] entityBytes = responseWrapper.getEntityBytes();
            ZimbraLog.extensions.debug("The Content-Type: %s", ctype);
            if (entityBytes != null && StringUtils.startsWith(ctype, "image/")) {
                ZimbraLog.extensions.debug("Creating image attachment: %s as key: %s", filename, key);
                return new Attachment(entityBytes, ctype, key, filename);
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
    public static String executeRequest(HttpRequestBase request)
        throws ServiceException, IOException {
        final HttpClient client = OAuth2Utilities.getHttpClient();
        return executeRequest(client, request);
    }

    /**
     * Executes an Http Request and returns the raw response.
     *
     * @param request Request to execute
     * @return The raw response
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static HttpResponseWrapper executeRequestRaw(HttpRequestBase request)
        throws ServiceException, IOException {
        final HttpClient client = OAuth2Utilities.getHttpClient();
        return executeRequestRaw(client, request);
    }

    /**
     * Executes an Http Request with a given client and returns the response body.<br>
     * Returns null if there is no response body.
     *
     * @param client The client to execute with
     * @param request Request to execute
     * @return Response body as a string
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static String executeRequest(HttpClient client, HttpRequestBase request)
        throws ServiceException, IOException {
        final HttpResponseWrapper response = executeRequestRaw(client, request);
        final byte [] entity = response.getEntityBytes();
        if (entity == null) {
            return null;
        }
        return new String(entity);
    }

    /**
     * Executes an Http Request with a given client and returns the
     * raw response and body in a wrapper.
     *
     * @param client The client to execute with
     * @param request Request to execute
     * @return The raw response object and body in a wrapper
     * @throws ServiceException If there are issues with the connection
     * @throws IOException If there are non connection related issues
     */
    public static HttpResponseWrapper executeRequestRaw(HttpClient client, HttpRequestBase request)
        throws ServiceException, IOException {
        try {
            final HttpResponse response = HttpClientUtil.executeMethod(client, request);
            // read response body and add to wrapper before closing request connection
            return new HttpResponseWrapper(response, decodeEntity(response.getEntity()));
        } catch (final UnknownHostException e) {
            ZimbraLog.extensions.errorQuietly(
                "The configured destination address is unknown: " + request.getURI(), e);
            throw ServiceException
                .RESOURCE_UNREACHABLE("The configured destination address is unknown.", e);
        } catch (final SocketTimeoutException e) {
            ZimbraLog.extensions
                .error("The destination server took too long to respond to our request.");
            throw ServiceException.RESOURCE_UNREACHABLE(
                "The destination server took too long to respond to our request.", e);
        } catch (final ConnectionPoolTimeoutException e) {
            ZimbraLog.extensions
                .error("Too many active HTTP client connections, not enough resources available.");
            throw ServiceException.TEMPORARILY_UNAVAILABLE();
        } catch (final HttpException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue executing the request.", e);
            throw ServiceException
                .RESOURCE_UNREACHABLE("There was an issue executing the request.", null);
        } finally {
            if (request != null) {
                request.releaseConnection();
            }
        }
    }

    /**
     * Get an instance of HttpClient which is configured to use Zimbra proxy.
     *
     * @return HttpClient A HttpClient instance
     */
    public static HttpClient getHttpClient() {
        final HttpClientBuilder builder = ZimbraHttpConnectionManager.getExternalHttpConnMgr()
            .newHttpClient();
        HttpProxyUtil.configureProxy(builder);
        return builder.build();
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
    public static JsonNode stringToJson(String jsonString) throws IOException {
        return OAuth2JsonUtilities.stringToJson(jsonString);
    }

}
