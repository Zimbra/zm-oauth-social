package com.zimbra.oauth.token.utilities;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.models.OAuthInfo;
import com.zimbra.oauth.utilities.OAuth2HttpConstants;
import com.zimbra.oauth.utilities.OAuth2Utilities;

/**
 * @author zimbra
 *
 */
public final class OAuth2HandlerUtilities {

    /**
     * @see #getTokenRequest(OAuthInfo, String, Map)
     */
    public static JsonNode getTokenRequest(OAuthInfo authInfo, String basicToken)
        throws ServiceException {
        return getTokenRequest(authInfo, basicToken, Collections.emptyMap());
    }

    /**
     * Default get_token implementation, usable by standard oauth2 services.<br>
     * Builds and executes the get_token HTTP request for the client.
     *
     * @param authInfo Contains the auth info to use in the request
     * @param basicToken The basic authorization header
     * @param extraHeaders Non-null map of extra token headers to add
     * @return Json response from the endpoint containing credentials
     * @throws ServiceException If there are issues performing the request or
     *             parsing for json
     */
    public static JsonNode getTokenRequest(OAuthInfo authInfo, String basicToken,
        Map<String, String> extraHeaders) throws ServiceException {
        final String refreshToken = authInfo.getRefreshToken();
        final HttpPost request = new HttpPost(authInfo.getTokenUrl());
        final List<NameValuePair> params = new ArrayList<NameValuePair>();
        if (!StringUtils.isEmpty(refreshToken)) {
            // set refresh token if we have one
            params.add(new BasicNameValuePair("grant_type", "refresh_token"));
            params.add(new BasicNameValuePair("refresh_token", refreshToken));
        } else {
            // otherwise use the code
            params.add(new BasicNameValuePair("grant_type", "authorization_code"));
            params.add(new BasicNameValuePair("code", authInfo.getParam("code")));
        }
        params.add(new BasicNameValuePair("redirect_uri", authInfo.getClientRedirectUri()));
        params.add(new BasicNameValuePair("client_secret", authInfo.getClientSecret()));
        params.add(new BasicNameValuePair("client_id", authInfo.getClientId()));
        // add extra headers
        extraHeaders.forEach((k, v) -> params.add(new BasicNameValuePair(k, v)));
        setFormEntity(request, params);
        request.setHeader(OAuth2HttpConstants.HEADER_CONTENT_TYPE.getValue(),
            "application/x-www-form-urlencoded");
        request.setHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(),
            "Basic " + basicToken);
        JsonNode json = null;
        try {
            json = OAuth2Utilities.executeRequestForJson(request);
            ZimbraLog.extensions.debug("Request for auth token completed.");
        } catch (final IOException e) {
            ZimbraLog.extensions
                .errorQuietly("There was an issue acquiring the authorization token.", e);
            throw ServiceException
                .PERM_DENIED("There was an issue acquiring an authorization token for this user.");
        }

        return json;
    }

    /**
     * Sets a specified form encoded param entity on the request.
     *
     * @param request The request to set the entity on
     * @param params The params to set
     * @throws ServiceException If there are issues encoding
     */
    public static void setFormEntity(HttpPost request, List<NameValuePair> params)
        throws ServiceException {
        try {
            request.setEntity(new UrlEncodedFormEntity(params));
        } catch (final UnsupportedEncodingException e) {
            ZimbraLog.extensions.error("Unable to encode token request params %s", params);
            ZimbraLog.extensions.debug(e);
            throw ServiceException.INVALID_REQUEST("Unable to encode token request params.", null);
        }
    }


}
