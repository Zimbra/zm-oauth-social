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

import org.apache.http.HttpResponse;

/**
 * The HttpResponseWrapper class.<br>
 * Wrapper for HttpResponse contains entity as byte array.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2019
 */
public class HttpResponseWrapper {

    /**
     * The http response.
     */
    protected HttpResponse response;

    /**
     * The http entity.
     */
    protected byte[] entityBytes;

    /**
     * Creates an instance with response and entity.
     *
     * @param response The response to set
     * @param entityBytes The entity bytes to set
     */
    public HttpResponseWrapper(HttpResponse response, byte[] entityBytes) {
        this.response = response;
        this.entityBytes = entityBytes;
    }

    /**
     * @return the response
     */
    public HttpResponse getResponse() {
        return response;
    }

    /**
     * @param response the response to set
     */
    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    /**
     * @return the entity bytes
     */
    public byte[] getEntityBytes() {
        return entityBytes;
    }

    /**
     * @param entityBytes the entity to set
     */
    public void setEntityBytes(byte[] entityBytes) {
        this.entityBytes = entityBytes;
    }

}
