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


/**
 * The OAuth2HttpConstants class.<br>
 * OAuth2HttpConstants contains http-related constants used in the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public enum OAuth2HttpConstants {

    HEADER_AUTHORIZATION("Authorization"),
    HEADER_CONTENT_TYPE("Content-Type"),
    HEADER_ACCEPT("Accept"),
    HEADER_LOCATION("Location"),
    HEADER_DISABLE_EXTERNAL_REQUESTS("Disable-External-Requests"),
    QUERY_ERROR("error"),
    QUERY_ERROR_MSG("error_msg"),
    COOKIE_AUTH_TOKEN("ZM_AUTH_TOKEN"),

    OAUTH2_RELAY_KEY("state"),
    OAUTH2_TYPE_KEY("type"),

    JWT_PARAM_KEY("jwt");

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
    private OAuth2HttpConstants(String constant) {
        this.constant = constant;
    }

}
