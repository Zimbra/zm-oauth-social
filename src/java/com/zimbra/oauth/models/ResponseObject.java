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
package com.zimbra.oauth.models;

import javax.xml.bind.annotation.XmlRootElement;

import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The ResponseObject class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2018
 */
@XmlRootElement
public class ResponseObject<E> {

    /**
     * Data of type.
     */
    protected E data;

    /**
     * Meta instance.
     */
    protected Meta _meta = new Meta();

    /**
     * Constructor.
     *
     * @param data A data object
     */
    public ResponseObject(E data) {
        this.data = data;
    }

    /**
     * Get data.
     *
     * @return A data object
     */
    public E getData() {
        return data;
    }

    /**
     * Set data.
     *
     * @param data A data object
     */
    public void setData(E data) {
        this.data = data;
    }

    /**
     * Get the Meta instance.
     *
     * @return The instance of Meta object
     */
    public Meta get_meta() {
        return _meta;
    }

    /**
     * Set the Meta instance.
     *
     * @param _meta An instance of Meta object
     */
    public void set_meta(Meta _meta) {
        this._meta = _meta;
    }

    @XmlRootElement
    protected class Meta {

        protected final String api = OAuth2Constants.API_NAME;

        public String getApi() {
            return api;
        }
    }
}
