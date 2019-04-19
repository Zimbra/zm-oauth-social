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

import org.apache.http.Consts;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthSchemeProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.impl.auth.BasicSchemeFactory;

import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.cs.dav.DavContext.Depth;
import com.zimbra.cs.dav.client.CalDavClient;

/**
 * The CalDavOAuth2Client class.<br>
 * Used to refresh OAuth2 access token for CalDav import.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class CalDavOAuth2Client extends CalDavClient {

    /**
     * Constructor.
     *
     * @param baseUrl The url to initialize with
     */
    public CalDavOAuth2Client(String baseUrl) {
        super(baseUrl);
    }

    @Override
    protected HttpResponse executeMethod(HttpRequestBase m, Depth d, String bodyForLogging) throws IOException, HttpException {
        final Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
            .register(AuthSchemes.BASIC, new BasicSchemeFactory(Consts.UTF_8)).build();
        mClient.setDefaultAuthSchemeRegistry(authSchemeRegistry);
        final HttpClient client = mClient.build();
        m.setHeader("User-Agent", mUserAgent);
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
        m.setHeader("Depth", depth);
        final String authorizationHeader = String.format("Bearer %s", accessToken);
        m.addHeader(OAuth2HttpConstants.HEADER_AUTHORIZATION.getValue(), authorizationHeader);
        m.setHeader("Depth", depth);
        logRequestInfo(m, bodyForLogging);
        final HttpResponse response = HttpClientUtil.executeMethod(client, m);
        logResponseInfo(response);
        return response;
    }
}
