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

/**
 * The ErrorMessage class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2019
 */
@XmlRootElement
public class ErrorMessage {

    /**
     * Error code.
     */
    protected String code;

    /**
     * Error message.
     */
    protected String message;

    /**
     * @param code The error code
     */
    public ErrorMessage(String code) {
        this(code, null);
    }

    /**
     * @param code The error code
     * @param message The error message
     */
    public ErrorMessage(String code, String message) {
        this.code = code;
        this.message = message;
    }

    /**
     * @return the code
     */
    public String getCode() {
        return code;
    }

    /**
     * @param code the code to set
     */
    public void setCode(String code) {
        this.code = code;
    }

    /**
     * @return The error message
     */
    public String getMessage() {
        return message;
    }

    /**
     * @param message The error message
     */
    public void setMessage(String message) {
        this.message = message;
    }

}
