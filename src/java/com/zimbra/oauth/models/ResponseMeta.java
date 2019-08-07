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

import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The ResponseMeta class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2019
 */
@XmlRootElement
public class ResponseMeta {

    protected final String api = OAuth2Constants.API_NAME.getValue();

    /**
     * HTTP Status.
     */
    @JsonIgnore
    protected int status;

    /**
     * Constructor.
     *
     * @param status The status to set
     */
    public ResponseMeta(int status) {
        this.status = status;
    }

    public String getApi() {
        return api;
    }

    /**
     * @return the status
     */
    public int getStatus() {
        return status;
    }

    /**
     * @param status the status to set
     */
    public void setStatus(int status) {
        this.status = status;
    }

}
