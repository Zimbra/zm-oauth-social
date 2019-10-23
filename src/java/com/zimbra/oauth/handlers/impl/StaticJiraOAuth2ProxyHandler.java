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

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.core.MediaType;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;

import com.google.common.collect.ImmutableMap;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.oauth.handlers.IOAuth2ProxyHandler;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2ProxyUtilities;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The StaticJiraOAuth2ProxyHandler class.<br>
 * Handles token fetching for Jira projects with predetermined credentials.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class StaticJiraOAuth2ProxyHandler extends StaticOAuth2ProxyHandler implements IOAuth2ProxyHandler {

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum StaticJiraOAuth2ProxyHandlerConstants {

        /**
         * The issue API uri template.
         */
        ISSUE_URI_TEMPLATE("%s/rest/api/3/issue");

        /**
         * The value of this enum.
         */
        private final String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private StaticJiraOAuth2ProxyHandlerConstants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Allowed target proxy path for static jira.
     */
    protected Map<String, Pattern> allowedTargetPaths = ImmutableMap.of(
        "POST", Pattern.compile("^(/rest/api/3/issue)/?(?:([^/]+)/attachments)??$")
    );

    @Override
    public boolean isProxyRequestAllowed(String client, String method,
        Map<String, String> extraHeaders, String target, byte[] body, Account account) {
        URIBuilder builder;
        try {
            builder = new URIBuilder(target);
        } catch (final URISyntaxException e) {
            ZimbraLog.extensions.warn("Unable to parse proxy target: %s", target);
            return false;
        }
        final String requestPath = builder.getPath();
        final String projectId = StringUtils.substringAfterLast(client, "-");
        Matcher issueMatcher;
        return requestPath != null
            // validate host
            && OAuth2ProxyUtilities.isAllowedTargetHost(builder.getHost(), account)
            // validate path
            && allowedTargetPaths.containsKey(method)
            && (issueMatcher = allowedTargetPaths.get(method).matcher(requestPath)).matches()
            // only allow requests on the project associated with the credentials
            && isAllowedTargetProject(projectId,
                getIssueApi(target, issueMatcher.group(1)),
                issueMatcher.groupCount() >= 2 ? issueMatcher.group(2) : null,
                extraHeaders.get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue()), body);
    }

    /**
     * Determines if the request references the allowed project for the credentials.<br>
     * Returns false if the allowedProjectId is empty or null.
     *
     * @param allowedProjectId The allowed project id
     * @param issueApi The issue api url
     * @param issueId The request path issueId
     * @param authHeader Authorization header for jira requests
     * @param body The request body
     * @return True if the request targets the allowed project
     */
    protected boolean isAllowedTargetProject(String allowedProjectId,
        String issueApi, String issueId, String authHeader, byte[] body) {
        if (StringUtils.isEmpty(allowedProjectId)) {
            return false;
        }
        if (issueId != null) {
            // validate add attachment issue's project id
            final String issueProjectId = getProjectIdFromIssue(issueApi, issueId, authHeader);
            ZimbraLog.extensions.debug("Jira issue project id: %s", issueProjectId);
            return allowedProjectId.equals(issueProjectId);
        }
        try {
            // validate create issue project
            final Map<String, Object> requestBody = OAuth2JsonUtilities.bytesToMap(body);
            final String projectIdParam = getProjectIdFromBody(requestBody);
            ZimbraLog.extensions.debug("Jira project id: %s", projectIdParam);
            return allowedProjectId.equals(projectIdParam);
        } catch (ClassCastException | ServiceException e) {
            ZimbraLog.extensions.warnQuietly(
                "Unable to determine if create jira issue request targets allowed project.", e);
            return false;
        }
    }

    protected String getProjectIdFromIssue(String issueApi, String issueId, String authHeader) {
        final HttpGet request = new HttpGet(issueApi + "/" + issueId);
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authHeader);
        try {
            final HttpResponseWrapper res = OAuth2Utilities.executeRequestRaw(request);
            // return nothing if not a json response
            final String contentType = res.getResponse()
                .getFirstHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue()).getValue();
            if (!StringUtils.startsWithIgnoreCase(contentType, MediaType.APPLICATION_JSON)) {
                ZimbraLog.extensions
                    .warn("Invalid response type when fetching issue project id: %s", contentType);
                return null;
            }
            return getProjectIdFromBody(
                OAuth2JsonUtilities.stringToMap(new String(res.getEntityBytes())));
        } catch (ServiceException | IOException e) {
            ZimbraLog.extensions.errorQuietly(String.format(
                "Failed to determine project id from issue: %s via API: %s", issueId, issueApi), e);
            return null;
        }
    }

    protected String getIssueApi(String target, String issuePath) {
        return String.format(StaticJiraOAuth2ProxyHandlerConstants.ISSUE_URI_TEMPLATE.getValue(),
            StringUtils.substringBefore(target, issuePath));
    }

    @SuppressWarnings("unchecked")
    protected String getProjectIdFromBody(Map<String, Object> body) {
        final Map<String, Object> fieldsParams = (Map<String, Object>) body.getOrDefault("fields",
            Collections.emptyMap());
        final Map<String, Object> projectParams = (Map<String, Object>) fieldsParams
            .getOrDefault("project", Collections.emptyMap());
        return (String) projectParams.get("id");
    }

}
