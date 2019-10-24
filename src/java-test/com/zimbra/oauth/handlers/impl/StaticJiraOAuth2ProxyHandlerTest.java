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
package com.zimbra.oauth.handlers.impl;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.MediaType;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.message.BasicHeader;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.google.common.collect.ImmutableMap;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ProxyUtilities;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * Test class for {@link StaticJiraOAuth2ProxyHandler}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ StaticJiraOAuth2ProxyHandler.class, OAuth2Utilities.class, OAuth2ProxyUtilities.class })
public class StaticJiraOAuth2ProxyHandlerTest {

    /**
     * Class under test.
     */
    protected StaticJiraOAuth2ProxyHandler handler = new StaticJiraOAuth2ProxyHandler();

    /**
     * Jira project id.
     */
    protected final String projectId = "12345";

    /**
     * Client for testing.
     */
    protected final String client = String.format("static-basic-jira-%s", projectId);

    /**
     * Authorization header for testing.
     */
    protected final String authHeader = String.format("Basic %s",
        OAuth2Utilities.encodeBasicHeader("test@zmc.com", "testToken"));

    /**
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        PowerMock.mockStatic(OAuth2Utilities.class);
        PowerMock.mockStatic(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns true when
     * creating an issue.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssue() throws Exception {
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = buildRequestBodyJson(projectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertTrue(handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when
     * invalid projectId is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueForbiddenProjectId() throws Exception {
        final String forbiddenProjectId = "forbiddenProjectId";
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = buildRequestBodyJson(forbiddenProjectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when null
     * projectId is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueNullProjectId() throws Exception {
        final String noProjectId = null;
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = buildRequestBodyJson(noProjectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when null
     * body is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueNullBody() throws Exception {
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = null;

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when
     * forbidden host is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueForbiddenHost() throws Exception {
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = buildRequestBodyJson(projectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(false);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when
     * forbidden path is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueForbiddenPath() throws Exception {
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/2/forbidden/path/", host);
        final byte[] body = buildRequestBodyJson(projectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false when
     * forbidden method is specified.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedCreateIssueForbiddenMethod() throws Exception {
        final String method = HttpMethod.DELETE;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String target = String.format("https://%s/rest/api/3/issue/", host);
        final byte[] body = buildRequestBodyJson(projectId).getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    /**
     * Test method for {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns true on happy
     * path when adding an attachment.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedAddAttachment() throws Exception {
        final String method = HttpMethod.POST;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String issueId = "5555";
        final String target = String.format("https://%s/rest/api/3/issue/%s/attachments", host,
            issueId);
        final String jsonBody = buildRequestBodyJson(projectId);
        final byte[] body = jsonBody.getBytes();
        final HttpResponseWrapper mockResponseWrapper = EasyMock
            .createMock(HttpResponseWrapper.class);
        final HttpResponse mockHttpResponse = EasyMock.createMock(HttpResponse.class);
        final String contentHeaderName = OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);
        expect(mockResponseWrapper.getResponse()).andReturn(mockHttpResponse);
        expect(mockResponseWrapper.getEntityBytes()).andReturn(jsonBody.getBytes());
        expect(mockHttpResponse.getFirstHeader(contentHeaderName))
            .andReturn(new BasicHeader(contentHeaderName, MediaType.APPLICATION_JSON));
        expect(OAuth2Utilities.executeRequestRaw(anyObject(HttpRequestBase.class)))
            .andReturn(mockResponseWrapper);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);
        replay(mockResponseWrapper);
        replay(mockHttpResponse);

        assertTrue(handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
        verify(mockResponseWrapper);
        verify(mockHttpResponse);
    }

    /**
     * Test method for
     * {@link StaticJiraOAuth2ProxyHandler#isProxyRequestAllowed}<br>
     * Validates that the isProxyRequestAllowed method returns false on
     * forbidden method when adding an attachment.
     *
     * @throws Exception
     *             If there are issues testing
     */
    @Test
    public void testIsProxyRequestAllowedAddAttachmentForbiddenMethod() throws Exception {
        final String method = HttpMethod.DELETE;
        final Map<String, String> extraHeaders = ImmutableMap
            .of(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        final String host = "zimbra.test";
        final String issueId = "5555";
        final String target = String.format("https://%s/rest/api/3/issue/%s/attachments", host,
            issueId);
        final String jsonBody = buildRequestBodyJson(projectId);
        final byte[] body = jsonBody.getBytes();

        expect(OAuth2ProxyUtilities.isAllowedTargetHost(matches(host), anyObject(Account.class)))
            .andReturn(true);

        PowerMock.replay(OAuth2Utilities.class);
        PowerMock.replay(OAuth2ProxyUtilities.class);

        assertFalse(
            handler.isProxyRequestAllowed(client, method, extraHeaders, target, body, null));

        PowerMock.verify(OAuth2Utilities.class);
        PowerMock.verify(OAuth2ProxyUtilities.class);
    }

    protected String buildRequestBodyJson(String projectId) throws ServiceException {
        final Map<String, Object> project = new HashMap<String, Object>();
        project.put("id", projectId);
        final Map<String, Object> fields = new HashMap<String, Object>();
        fields.put("project", project);
        final Map<String, Object> body = new HashMap<String, Object>();
        body.put("fields", fields);
        return OAuth2JsonUtilities.objectToJson(body);
    }

}
