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
package com.zimbra.oauth.models;

import java.util.Collections;
import java.util.Map;

/**
 * The GuestRequest class.<br>
 * Contains request headers and body.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2019
 */
public class GuestRequest {

    /**
     * Relevant request headers.
     */
    private Map<String, String> headers;

    /**
     * Request body params.
     */
    private Map<String, Object> body;

    public GuestRequest() {
        this(Collections.emptyMap(), Collections.emptyMap());
    }

    public GuestRequest(Map<String, String> headers, Map<String, Object> body) {
        this.headers = headers;
        this.body = body;
    }

    /**
     * @return the headers
     */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /**
     * @param headers the headers to set
     */
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    /**
     * @return the body
     */
    public Map<String, Object> getBody() {
        return body;
    }

    /**
     * @param body the body to set
     */
    public void setBody(Map<String, Object> body) {
        this.body = body;
    }

}
