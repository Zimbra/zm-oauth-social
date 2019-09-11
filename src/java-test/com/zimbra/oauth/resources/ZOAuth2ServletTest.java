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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.zimbra.oauth.models.ResponseMeta;
import com.zimbra.oauth.models.ResponseObject;
import com.zimbra.oauth.utilities.OAuth2Constants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

/**
 * Test class for {@link ZOAuth2Servlet}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ OAuth2JsonUtilities.class, OAuth2ResourceUtilities.class, ZOAuth2Servlet.class })
public class ZOAuth2ServletTest {

    /**
     * Mock servlet.
     */
    protected ZOAuth2Servlet servlet = new ZOAuth2Servlet();

    /**
     * Mock request for testing.
     */
    protected HttpServletRequest mockRequest = EasyMock.createMock(HttpServletRequest.class);

    /**
     * Mock response for testing.
     */
    protected HttpServletResponse mockResponse = EasyMock.createMock(HttpServletResponse.class);

    /**
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        PowerMock.mockStatic(OAuth2JsonUtilities.class);
        PowerMock.mockStatic(OAuth2ResourceUtilities.class);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doPost}<br>
     * Validates that the event handler is called.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoPostEvent() throws Exception {
        // path
        final String action = "event";
        final String client = "test-client";
        final String path = String.format("%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client);
        // header
        final String authHeader = "verification-token";
        // body
        final Map<String, Object> bodyParams = new HashMap<String, Object>();
        bodyParams.put("event", "test");
        bodyParams.put("payload", Collections.emptyMap());

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch the body
        expect(mockRequest.getInputStream()).andReturn(null);
        // expect to fetch the auth header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()))
            .andReturn(authHeader);
        // expect to fetch disable header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()))
            .andReturn(null);
        // expect to parse the body
        expect(OAuth2JsonUtilities.streamToMap(anyObject())).andReturn(bodyParams);
        // expect to call event handler
        OAuth2ResourceUtilities.event(matches(client), anyObject(), eq(bodyParams));
        PowerMock.expectLastCall().once();
        // expect to send an Accepted status then flush buffer
        mockResponse.setStatus(Status.ACCEPTED.getStatusCode());
        PowerMock.expectLastCall().once();
        mockResponse.flushBuffer();
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doPost(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doPost}<br>
     * Validates that an error response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoPostInvalidAction() throws Exception {
        // path
        final String action = "not-an-action";
        final String client = "test-client";
        final String path = String.format("%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client);

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        mockResponse.sendError(Status.BAD_REQUEST.getStatusCode());
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(mockResponse);

        servlet.doPost(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doGet}<br>
     * Validates that the authorize handler is called and a
     * redirect response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoGetAuthorize() throws Exception {
        // path
        final String action = "authorize";
        final String client = "test-client";
        final String path = String.format("%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client);
        final String location = "/";
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections
            .singletonMap(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), null);
        final Map<String, String[]> params = Collections.emptyMap();

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the auth header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()))
            .andReturn(null);
        // expect to fetch disable header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()))
            .andReturn(null);
        // expect to fetch the request params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to call authorize handler
        OAuth2ResourceUtilities.authorize(matches(client), eq(cookies), eq(headers), eq(params));
        PowerMock.expectLastCall().andReturn(location);
        // expect to send a redirect
        mockResponse.sendRedirect(location);
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doGet(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doGet}<br>
     * Validates that the authenticate handler is called and a
     * redirect response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoGetAuthenticate() throws Exception {
        // path
        final String action = "authenticate";
        final String client = "test-client";
        final String path = String.format("%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client);
        final String location = "/";
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections
            .singletonMap(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), null);
        final Map<String, String[]> params = Collections.emptyMap();

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the auth header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()))
            .andReturn(null);
        // expect to fetch disable header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()))
            .andReturn(null);
        // expect to fetch the request params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to call authenticate handler
        OAuth2ResourceUtilities.authenticate(matches(client), eq(cookies), eq(headers), eq(params));
        PowerMock.expectLastCall().andReturn(location);
        // expect to send a redirect
        mockResponse.sendRedirect(location);
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doGet(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doGet}<br>
     * Validates that the refresh handler is called and a
     * json response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoGetRefresh() throws Exception {
        // path
        final String action = "refresh";
        final String client = "test-client";
        final String identifier = "test@zmc.com";
        final String output = "test";
        final int status = Status.OK.getStatusCode();
        final String path = String.format("%s/%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client, identifier);
        final ResponseObject<String> responseObject = new ResponseObject<String>(output,
            new ResponseMeta(status));
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections
            .singletonMap(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), null);
        final Map<String, String[]> params = Collections.emptyMap();

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the auth header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()))
            .andReturn(null);
        // expect to fetch disable header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()))
            .andReturn(null);
        // expect to fetch the request params
        expect(mockRequest.getParameterMap()).andReturn(params);
        // expect to call refresh handler
        OAuth2ResourceUtilities.refresh(matches(client), matches(identifier), eq(cookies),
            eq(headers), eq(params));
        PowerMock.expectLastCall().andReturn(responseObject);
        // expect to print some results
        mockResponse.setStatus(status);
        PowerMock.expectLastCall().once();
        mockResponse.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        PowerMock.expectLastCall().once();
        mockResponse.getWriter();
        PowerMock.expectLastCall().andReturn(EasyMock.createMock(PrintWriter.class));
        expect(OAuth2JsonUtilities.objectToJson(anyObject())).andReturn(output);
        mockResponse.flushBuffer();
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doGet(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doGet}<br>
     * Validates that the info handler is called and a
     * json response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoGetInfo() throws Exception {
        // path
        final String action = "info";
        final String client = "test-client";
        final String output = "test";
        final int status = Status.OK.getStatusCode();
        final String path = String.format("%s/%s/%s/",
            OAuth2Constants.DEFAULT_SERVER_PATH.getValue(), action, client);
        final ResponseObject<String> responseObject = new ResponseObject<String>(output,
            new ResponseMeta(status));
        final Cookie[] cookies = new Cookie[] {};
        final Map<String, String> headers = Collections
            .singletonMap(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), null);

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        // expect to fetch cookies
        expect(mockRequest.getCookies()).andReturn(cookies);
        // expect to fetch the auth header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()))
            .andReturn(null);
        // expect to fetch disable header
        expect(mockRequest.getHeader(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()))
            .andReturn(null);
        // expect to call info handler
        OAuth2ResourceUtilities.info(matches(client), eq(cookies),
            eq(headers));
        PowerMock.expectLastCall().andReturn(responseObject);
        // expect to print some results
        mockResponse.setStatus(status);
        PowerMock.expectLastCall().once();
        mockResponse.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            MediaType.APPLICATION_JSON);
        PowerMock.expectLastCall().once();
        mockResponse.getWriter();
        PowerMock.expectLastCall().andReturn(EasyMock.createMock(PrintWriter.class));
        expect(OAuth2JsonUtilities.objectToJson(anyObject())).andReturn(output);
        mockResponse.flushBuffer();
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(OAuth2JsonUtilities.class);
        PowerMock.replay(OAuth2ResourceUtilities.class);
        PowerMock.replay(mockResponse);

        servlet.doGet(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(OAuth2JsonUtilities.class);
        PowerMock.verify(OAuth2ResourceUtilities.class);
        PowerMock.verify(mockResponse);
    }

    /**
     * Test method for {@link ZOAuth2Servlet#doGet}<br>
     * Validates that an error response is sent.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testDoGetInvalidAction() throws Exception {
        // path
        final String action = "not-an-action";
        final String client = "test-client";
        final String path = OAuth2Constants.DEFAULT_SERVER_PATH.getValue()
            + "/" + action + "/" + client + "/";

        // expect to fetch the path
        expect(mockRequest.getPathInfo()).andReturn(path);
        mockResponse.sendError(Status.BAD_REQUEST.getStatusCode());
        PowerMock.expectLastCall().once();

        replay(mockRequest);
        PowerMock.replay(mockResponse);

        servlet.doGet(mockRequest, mockResponse);

        verify(mockRequest);
        PowerMock.verify(mockResponse);
    }

}
