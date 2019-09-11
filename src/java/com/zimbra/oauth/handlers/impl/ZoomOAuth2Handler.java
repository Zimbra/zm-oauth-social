/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra OAuth2 Extension
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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.Response.Status;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.models.GuestRequest;
import com.zimbra.oauth.models.HttpResponseWrapper;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2CacheUtilities;
import com.zimbra.oauth.utilities.OAuth2ConfigConstants;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2JsonUtilities;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * The ZoomOAuth2Handler class.<br>
 * Zoom OAuth operations handler.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2019
 */
public class ZoomOAuth2Handler extends OAuth2Handler implements IOAuth2Handler {

    private final String ERROR_TEMPLATE = "%s | Zoom error code: %s | Reason: %s";

    /**
     * Contains error constants used in this implementation.
     */
    protected enum ZoomErrorConstants {

        /**
         * Invalid request response code from Zoom.
         */
        RESPONSE_ERROR_INVALID_REQUEST("invalid_request"),

        /**
         * Default error.
         */
        DEFAULT_ERROR("internal_error");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private ZoomErrorConstants(String constant) {
            this.constant = constant;
        }

        /**
         * ValueOf wrapper for constants.
         *
         * @param code The code to check for
         * @return Enum instance
         */
        protected static ZoomErrorConstants fromString(String code) {
            for (final ZoomErrorConstants t : ZoomErrorConstants.values()) {
                if (StringUtils.equals(t.getValue(), code)) {
                    return t;
                }
            }
            return DEFAULT_ERROR;
        }

    }

    /**
     * Contains oauth2 constants used in this implementation.
     */
    protected enum ZoomOAuth2Constants {

        /**
         * The authorize endpoint for Zoom.
         */
        AUTHORIZE_URI_TEMPLATE("https://zoom.us/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s"),

        /**
         * The profile endpoint for Zoom.
         */
        PROFILE_URI("https://zoom.us/v2/users/me"),

        /**
         * The authenticate endpoint for Zoom.
         */
        AUTHENTICATE_URI("https://zoom.us/oauth/token"),

        /**
         * The compliance endpoint for Zoom.
         */
        COMPLIANCE_URI("https://api.zoom.us/oauth/data/compliance"),

        /**
         * The scope required for Zoom.
         */
        REQUIRED_SCOPES("user:read"),

        /**
         * The scope delimiter for Zoom.
         */
        SCOPE_DELIMITER("+"),

        /**
         * Format for identifier as: `account id-user id`.
         */
        IDENTIFIER_TEMPLATE("%s-%s"),

        /**
         * The relay key for Zoom.
         */
        RELAY_KEY("state"),

        /**
         * The implementation name.
         */
        CLIENT_NAME("zoom"),

        /**
         * The implementation host.
         */
        HOST_ZOOM("zoom.us");

        /**
         * The value of this enum.
         */
        private String constant;

        /**
         * @return The enum value
         */
        public String getValue() {
            return constant;
        }

        /**
         * @param constant The enum value to set
         */
        private ZoomOAuth2Constants(String constant) {
            this.constant = constant;
        }

    }

    /**
     * Constructs a ZoomOAuth2Handler object.
     *
     * @param config For accessing configured properties
     */
    public ZoomOAuth2Handler(Configuration config) {
        super(config, ZoomOAuth2Constants.CLIENT_NAME.getValue(), ZoomOAuth2Constants.HOST_ZOOM.getValue());
        authenticateUri = ZoomOAuth2Constants.AUTHENTICATE_URI.getValue();
        authorizeUriTemplate = ZoomOAuth2Constants.AUTHORIZE_URI_TEMPLATE.getValue();
        requiredScopes = ZoomOAuth2Constants.REQUIRED_SCOPES.getValue();
        scopeDelimiter = ZoomOAuth2Constants.SCOPE_DELIMITER.getValue();
        relayKey = ZoomOAuth2Constants.RELAY_KEY.getValue();
    }

    @Override
    protected void setResponseParams(JsonNode tokenResponse, OAuthInfo oauthInfo) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("access_token", tokenResponse.get("access_token").asText());
        params.put("user_id", oauthInfo.getUsername());
        oauthInfo.setParams(params);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Boolean event(GuestRequest request) throws ServiceException {
        final Map<String, Object> body = request.getBody();
        final Map<String, String> headers = request.getHeaders();

        // fetch the payload
        final Object rawPayload = body.get("payload");
        Map<String, String> payload = null;
        if (rawPayload == null || !(rawPayload instanceof Map)) {
            ZimbraLog.extensions.warn("invalid oauth deauthorization request: missing payload.");
            return false;
        }
        payload = (Map<String, String>) rawPayload;

        // handle events
        final String event = (String) body.getOrDefault("event", "");
        switch (event) {
        case "app_deauthorized":
            return deauthorize(headers, payload);
        default:
            return false;
        }
    }

    /**
     * Validates that the token response has no errors, and contains the
     * requested access information.
     *
     * @param response The json token response
     * @throws ServiceException<br>
     *             OPERATION_DENIED If the refresh token request was deemed invalid due
     *             to inorrect request parameters (code, client id/secret, etc).<br>
     *             PARSE_ERROR If the response from Zoom has no errors, but
     *             the access info is missing.<br>
     *             PERM_DENIED If the refresh token or code is expired, or for
     *             general rejection.
     */
    @Override
    protected void validateTokenResponse(JsonNode response) throws ServiceException {
        // check for errors
        if (response.has("error")) {
            final String error = response.get("error").asText();
            String errorMsg = error;
            if (response.has("reason")) {
                errorMsg = response.get("reason").asText();
            }
            ZimbraLog.extensions.debug("Response from zoom: %s", response.asText());
            switch (ZoomErrorConstants.fromString(StringUtils.lowerCase(error))) {
            case RESPONSE_ERROR_INVALID_REQUEST:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Invalid oauth token request parameter(s) provided, check configuration.",
                    error, errorMsg));
                throw ServiceException
                    .OPERATION_DENIED("Invalid oauth token request parameter(s) provided.");
            default:
                ZimbraLog.extensions.warn(String.format(ERROR_TEMPLATE,
                    "Unexpected error while trying to authenticate the user.", error, errorMsg));
                throw ServiceException.PERM_DENIED("Unable to authenticate the user.");
            }
        }

        // ensure the tokens we requested are present
        if (!response.has("access_token") || !response.has("refresh_token")) {
            throw ServiceException.PARSE_ERROR(
                "Unexpected response from social service. Missing any of required params: access_token, refresh_token.",
                null);
        }

    }

    @Override
    protected String getPrimaryEmail(JsonNode credentials, Account account)
        throws ServiceException {
        final String authToken = credentials.get("access_token").asText();
        final HttpGet request = new HttpGet(ZoomOAuth2Constants.PROFILE_URI.getValue());
        request.setHeader(OAuth2HttpConstants.HEADER_ACCEPT.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer " + authToken);

        JsonNode json = null;
        try {
            json = executeRequestForJson(request);
        } catch (final IOException e) {
            ZimbraLog.extensions.errorQuietly("There was an issue acquiring the client's user info.", e);
            throw ServiceException.FAILURE("There was an issue acquiring the client's user info.", null);
        }

        if (json != null && json.hasNonNull("account_id") && json.hasNonNull("id")) {
            // build the Zoom user identifier
            final String zoomAccountId = json.get("account_id").asText();
            final String zoomUserId = json.get("id").asText();
            final String identifier = buildPrimaryIdentifier(zoomAccountId, zoomUserId);
            if (!StringUtils.isEmpty(identifier)) {
                final String zimbraAccountId = account.getId();
                ZimbraLog.extensions.debug(
                    "caching data for accountId: %s userId: %s zimbraAccountId: %s", zoomAccountId,
                    zoomUserId, zimbraAccountId);
                // cache Zoom -> Zimbra account mapping
                OAuth2CacheUtilities.put(buildCacheKey(identifier), zimbraAccountId);
                return identifier;
            }
        }

        // if we couldn't retrieve the handle identifier, the response from
        // downstream is missing data
        // this could be the result of a misconfigured application id/secret
        // (not enough scopes)
        ZimbraLog.extensions.error(
            "The primary id could not be retrieved from the profile api. Check social app's configured scopes.");
        throw ServiceException.UNSUPPORTED();
    }

    /**
     * Handles Zoom deauthorize event.
     *
     * @param headers The request headers
     * @param payload The request body in Map form
     * @return True if data retention in payload is false, and successfully sent data compliance request
     * @throws ServiceException If there are issues
     */
    protected Boolean deauthorize(Map<String, String> headers, Map<String, String> payload)
        throws ServiceException {
        final String payloadVerificationToken = headers
            .get(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue());
        // ensure authorization header is present
        if (StringUtils.isEmpty(payloadVerificationToken)) {
            ZimbraLog.extensions
                .error("invalid oauth deauthorization request: missing verification token.");
            return false;
        }
        // ensure data retention is false
        final String dataRetention = payload.get("user_data_retention");
        if (!StringUtils.equals("false", dataRetention)) {
            // otherwise we are finished complying with the event
            return true;
        }

        final OAuthInfo oauthInfo = new OAuthInfo(Collections.emptyMap());

        // based on the passed in zoom account+user id -> determine the zimbra account
        if (!loadZimbraAccount(payload.get("account_id"), payload.get("user_id"), oauthInfo)) {
            return false;
        }

        final Account account = oauthInfo.getAccount();
        final String identifier = oauthInfo.getUsername();
        // check for test header - default to sending if it is not true
        final Boolean doSendCompliance = !StringUtils.equals("true",
            headers.get(OAuth2HttpConstants.HEADER_DISABLE_EXTERNAL_REQUESTS.getValue()));

        // validate the request params and verification token
        if(!isValidEventRequest(account, payload, payloadVerificationToken, oauthInfo)
            // delete all datasources for the Zoom user
            || !dataSource.removeDataSources(account, identifier)
            // send compliance request
            || (doSendCompliance && !sendDataCompliance(payload, oauthInfo))) {
            return false;
        }

        // remove the account mapping from cache
        OAuth2CacheUtilities.remove(buildCacheKey(identifier));

        return true;
    }

    /**
     * Loads the Zimbra account and its app config associated with the accountId and userId.
     *
     * @param accountId The Zoom account id
     * @param userId The Zoom user id
     * @param oauthInfo The auth info to set the username and account on
     * @return True if no issues fetching a valid account or its app config
     * @throws ServiceException If there are issues getting the account or client config
     */
    protected boolean loadZimbraAccount(String accountId, String userId, OAuthInfo oauthInfo)
        throws ServiceException {
        final String identifier = buildPrimaryIdentifier(accountId, userId);
        final String cacheMappingKey = buildCacheKey(identifier);
        final String zimbraAccountId = OAuth2CacheUtilities.get(cacheMappingKey);
        final Account account = Provisioning.getInstance().getAccountById(zimbraAccountId);

        if (account == null) {
            // no account mapping found. do nothing since we can't validate the request.
            // this may happen if:
            //   * the request is not from zoom
            //   * the cache instance drops the data for this account
            ZimbraLog.extensions.warn(
                "unable to determine zimbra id for oauth deauthorization request. accountId: %s userId: %s",
                accountId, userId);
            return false;
        }
        oauthInfo.setUsername(identifier);
        oauthInfo.setAccount(account);
        // fetch client credentials
        loadClientConfig(account, oauthInfo);
        return true;
    }

    /**
     * Determines if the request for an event is valid.<br>
     * Ensures that the verification token is correct, per configuration.<br>
     * Ensures that the signature payload parameter is present.<br>
     * Ensures that the client_id is correct, per configuration.
     *
     * @param account The located account
     * @param payload The request payload
     * @param payloadVerificationToken The request authorization header
     * @param oauthInfo The client information loaded via the account
     * @return True if the event request has satisfactory identifying information
     */
    protected boolean isValidEventRequest(Account account, Map<String, String> payload,
        String payloadVerificationToken, OAuthInfo oauthInfo) {

        // verify requests's verification token
        final String verificationToken = config
            .getString(OAuth2ConfigConstants.OAUTH_VERIFICATION_TOKEN.getValue(), client, account);
        if (!StringUtils.equals(verificationToken, payloadVerificationToken)) {
            ZimbraLog.extensions.warn(
                "invalid oauth deauthorization verification token.",
                verificationToken, payloadVerificationToken);
            return false;
        }

        // TODO: verify the request matches signature (has not been modified)
        final String signature = payload.get("signature");
        if (StringUtils.isEmpty(signature)) {
            ZimbraLog.extensions
                .warn("invalid oauth deauthorization request: missing payload signature.");
            return false;
        }

        // ensure this account uses the client id specified in the request
        final String accountClientId = oauthInfo.getClientId();
        final String payloadClientId = payload.get("client_id");
        if (!StringUtil.equal(accountClientId, payloadClientId)) {
            ZimbraLog.extensions.warn(
                "incorrect deauthorization client id. expected: %s actual: %s", accountClientId,
                payloadClientId);
            return false;
        }

        return true;
    }

    /**
     * Sends a data compliance request to Zoom.
     *
     * @param payload The event payload
     * @param oauthInfo The auth info associated with the Zimbra user
     * @return True if the response is OK
     */
    protected boolean sendDataCompliance(Map<String, String> payload, OAuthInfo oauthInfo) {
        final String accountClientId = oauthInfo.getClientId();
        final String basicToken = OAuth2Utilities.encodeBasicHeader(
            accountClientId, oauthInfo.getClientSecret());
        final Map<String, Object> params = new HashMap<String, Object>();
        final HttpPost request = new HttpPost(ZoomOAuth2Constants.COMPLIANCE_URI.getValue());
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(), "application/json");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), "Bearer " + basicToken);
        params.put("client_id", accountClientId);
        params.put("user_id", payload.get("user_id"));
        params.put("account_id", payload.get("account_id"));
        params.put("deauthorization_event_received", payload);
        params.put("compliance_completed", true);

        try {
            final String json = OAuth2JsonUtilities.objectToJson(params);
            request.setEntity(new StringEntity(json, ContentType.APPLICATION_JSON));
            final HttpResponseWrapper response = OAuth2Utilities.executeRequestRaw(request);
            return Status.OK.getStatusCode() == response.getResponse().getStatusLine().getStatusCode();
        } catch (final ServiceException | IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue sending a compliance request to Zoom.", e);
            return false;
        }
    }

    /**
     * Builds a primary identifier for a Zoom user.
     *
     * @param accountId The Zoom account id
     * @param userId The Zoom user id
     * @return A primary identifier for a Zoom user
     */
    protected String buildPrimaryIdentifier(String accountId, String userId) {
        return String.format(ZoomOAuth2Constants.IDENTIFIER_TEMPLATE.getValue(), accountId, userId);
    }

    /**
     * Builds a prefixed cache key.
     *
     * @param identifier The Zoom account identifier
     * @return A prefixed key for use in cache
     */
    protected String buildCacheKey(String identifier) {
        // zm_oauth_social_zoom_{accountId-userId}
        return String.format("zm_oauth_social_%s_%s", client, identifier);
    }
}
