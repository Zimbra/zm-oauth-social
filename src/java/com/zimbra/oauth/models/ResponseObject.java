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
    protected final E data;

    /**
     * Meta instance.
     */
    protected final ResponseMeta _meta;

    /**
     * Constructor.
     *
     * @param data A data object
     */
    public ResponseObject(E data, ResponseMeta meta) {
        this.data = data;
        this._meta = meta;
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
     * Get the Meta instance.
     *
     * @return The instance of Meta object
     */
    public ResponseMeta get_meta() {
        return _meta;
    }

}
