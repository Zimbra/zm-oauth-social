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

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import java.io.PrintWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.google.common.collect.ImmutableMap;
import com.zimbra.cs.zimlet.ProxyServlet;
import com.zimbra.oauth.models.ErrorMessage;
import com.zimbra.oauth.models.HttpProxyServletRequest;
import com.zimbra.oauth.models.ResponseMeta;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2ErrorConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

/**
 * Test class for {@link ZOAuth2Servlet}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuth2JsonUtilities.class, OAuth2ResourceUtilities.class, ProxyServlet.class, ZOAuth2ProxyServlet.class })
public class ZOAuth2ProxyServletTest {

    /**
     * Mock servlet.
     */
    protected ZOAuth2ProxyServlet servlet;

    /**
     * Mock proxy servlet.
     */
    protected ProxyServlet mockProxyServlet = EasyMock.createMock(ProxyServlet.class);

    /**
     * Mock request for testing.
     */
    protected HttpServletRequest mockRequest = EasyMock.createMock(HttpServletRequest.class);

    /**
     * Mock response for testing.
     */
    protected HttpServletResponse mockResponse = EasyMock.createMock(HttpServletResponse.class);

    /**
     * Mock input stream for testing.
     */
    protected ServletInputStream mockStream = EasyMock.createMock(ServletInputStream.class);

    /**
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        PowerMock.mockStatic(OAuth2JsonUtilities.class);
        PowerMock.mockStatic(OAuth2ResourceUtilities.class);
        servlet = new ZOAuth2ProxyServlet(mockProxyServlet);
    }

    /**
     * Test method for {@link ZOAuth2ProxyServlet#doProxy}<br>
     * Validates that the headers handler, and proxy servlet service are called.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoProxy() throws Exception {
        final String method = HttpMethod.POST;
        final String client = "test-client";
        final String path = String.format("%s/%s/",
            OAuth2Constants.PROXY_SERVER_PATH.getValue(), client);
        final Cookie[] cookies = new Cookie[] {};
        final String headerName = "User-Agent";
        final Map<String, String> headers = ImmutableMap.of(headerName, "test");
        final Map<String, String[]> params = Collections.emptyMap();
        // body
        final Map<String, Object> bodyParams = new HashMap<String, Object>();
        bodyParams.put("action", "test");
        bodyParams.put("payload", Collections.emptyMap());
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "test-auth");

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch the cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the headers
        expect(mockRequest.getHeaderNames()).andReturn(Collections.enumeration(headers.keySet()));
        // expect to fetch the header
        expect(mockRequest.getHeader(headerName)).andReturn(headers.get(headerName));
        // expect to fetch the query params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to fetch the method
        expect(mockRequest.getMethod()).andReturn(method);
        // expect to fetch the body
        expect(mockRequest.getInputStream()).andReturn(mockStream);
        // expect to call event handler
        OAuth2ResourceUtilities.headers(matches(method), matches(client), eq(cookies),
            eq(headers), eq(params), eq(mockStream));
        PowerMock.expectLastCall().andReturn(new ResponseObject<Map<String, String>>(extraHeaders,
            new ResponseMeta(Status.OK.getStatusCode())));
        // expect to proxy service the request
        mockProxyServlet.service(anyObject(HttpProxyServletRequest.class), eq(mockResponse));
        EasyMock.expectLastCall();

        replay(mockRequest);
        replay(mockProxyServlet);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doProxy(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockProxyServlet);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2ProxyServlet#doProxy}<br>
     * Validates that the headers handler returns an error
     * if no valid Zimbra session is found.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoProxyNoZimbraAuth() throws Exception {
        final String method = HttpMethod.POST;
        final String client = "test-client";
        final String path = String.format("%s/%s/",
            OAuth2Constants.PROXY_SERVER_PATH.getValue(), client);
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections.emptyMap();
        final Map<String, String[]> params = Collections.emptyMap();
        // body
        final Map<String, Object> bodyParams = new HashMap<String, Object>();
        bodyParams.put("action", "test");
        bodyParams.put("payload", Collections.emptyMap());
        final ResponseObject<?> expectedResponse = new ResponseObject<ErrorMessage>(
            new ErrorMessage(OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue(),
                OAuth2ErrorConstants.ERROR_INVALID_ZM_AUTH_CODE_MSG.getValue()),
            new ResponseMeta(Status.UNAUTHORIZED.getStatusCode()));

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch the cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the headers
        expect(mockRequest.getHeaderNames()).andReturn(Collections.enumeration(headers.keySet()));
        // expect to fetch the query params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to fetch the method
        expect(mockRequest.getMethod()).andReturn(method);
        // expect to fetch the body
        expect(mockRequest.getInputStream()).andReturn(mockStream);
        // expect to call event handler
        OAuth2ResourceUtilities.headers(matches(method), matches(client), eq(cookies),
            eq(headers), eq(params), eq(mockStream));
        PowerMock.expectLastCall().andReturn(expectedResponse);
        // expect to send an error
        mockResponse.setStatus(Status.UNAUTHORIZED.getStatusCode());
        PowerMock.expectLastCall().once();
        mockResponse.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        PowerMock.expectLastCall().once();
        mockResponse.getWriter();
        PowerMock.expectLastCall().andReturn(EasyMock.createMock(PrintWriter.class));
        expect(OAuth2JsonUtilities.objectToJson(anyObject())).andReturn("");
        mockResponse.flushBuffer();
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        replay(mockProxyServlet);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doProxy(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockProxyServlet);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2ProxyServlet#doProxy}<br>
     * Validates that the headers handler is called and returns
     * an error if no proxy headers are found.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoProxyNoProxyHeaders() throws Exception {
        final String method = HttpMethod.POST;
        final String client = "test-client";
        final String path = String.format("%s/%s/",
            OAuth2Constants.PROXY_SERVER_PATH.getValue(), client);
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections.emptyMap();
        final Map<String, String[]> params = Collections.emptyMap();
        // body
        final Map<String, Object> bodyParams = new HashMap<String, Object>();
        bodyParams.put("action", "test");
        bodyParams.put("payload", Collections.emptyMap());
        final ResponseObject<?> expectedResponse = new ResponseObject<ErrorMessage>(
            new ErrorMessage(OAuth2ErrorConstants.ERROR_ACCESS_DENIED.getValue(), "No proxy auth found."),
            new ResponseMeta(Status.UNAUTHORIZED.getStatusCode()));

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch the cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the headers
        expect(mockRequest.getHeaderNames()).andReturn(Collections.enumeration(headers.keySet()));
        // expect to fetch the query params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to fetch the method
        expect(mockRequest.getMethod()).andReturn(method);
        // expect to fetch the body
        expect(mockRequest.getInputStream()).andReturn(mockStream);
        // expect to call event handler
        OAuth2ResourceUtilities.headers(matches(method), matches(client), eq(cookies),
            eq(headers), eq(params), eq(mockStream));
        PowerMock.expectLastCall().andReturn(expectedResponse);
        // expect to send an error
        mockResponse.setStatus(Status.UNAUTHORIZED.getStatusCode());
        PowerMock.expectLastCall().once();
        mockResponse.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        PowerMock.expectLastCall().once();
        mockResponse.getWriter();
        PowerMock.expectLastCall().andReturn(EasyMock.createMock(PrintWriter.class));
        expect(OAuth2JsonUtilities.objectToJson(anyObject())).andReturn("");
        mockResponse.flushBuffer();
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        replay(mockProxyServlet);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doProxy(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockProxyServlet);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

}
