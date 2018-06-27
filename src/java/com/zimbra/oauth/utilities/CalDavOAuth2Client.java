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
import java.util.ArrayList;

import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.AuthPolicy;
import org.apache.commons.httpclient.params.HttpMethodParams;

import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.cs.dav.DavContext.Depth;
import com.zimbra.cs.dav.client.CalDavClient;

public class CalDavOAuth2Client extends CalDavClient {

    public CalDavOAuth2Client(String baseUrl) {
        super(baseUrl);
    }

    protected HttpMethod executeMethod(HttpMethod m, Depth d, String bodyForLogging) throws IOException {
        HttpMethodParams p = m.getParams();
        if ( p != null )
            p.setCredentialCharset("UTF-8");

        m.setDoAuthentication(true);
        m.setRequestHeader("User-Agent", mUserAgent);
        String depth = "0";
        switch (d) {
        case one:
            depth = "1";
            break;
        case infinity:
            depth = "infinity";
            break;
        case zero:
            break;
        default:
            break;
        }
        m.setRequestHeader("Depth", depth);
        final String authorizationHeader = String.format("Bearer %s", accessToken);
        m.addRequestHeader(OAuth2Constants.HEADER_AUTHORIZATION, authorizationHeader);
        m.setRequestHeader("Depth", depth);
        logRequestInfo(m, bodyForLogging);
        ArrayList<String> authPrefs = new ArrayList<String>();
        authPrefs.add(AuthPolicy.BASIC);
        mClient.getParams().setParameter(AuthPolicy.AUTH_SCHEME_PRIORITY, authPrefs);
        mClient.getParams().setAuthenticationPreemptive(true);
        HttpClientUtil.executeMethod(mClient, m);
        logResponseInfo(m);
        return m;
    }
}
