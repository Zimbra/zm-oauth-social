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
 * The OAuth2Constants class.<br>
 * OAuth2Constants contains application constants used in the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public enum OAuth2Constants {

    API_NAME("zm-oauth-social"),
    ENCODING("utf-8"),
    DEFAULT_SERVER_PATH("/oauth2"),
    PROXY_SERVER_PATH("/oauth2-proxy"),

    DEFAULT_SUCCESS_REDIRECT("/"),
    DEFAULT_HOST_URI_TEMPLATE("https://%s:443"),
    DEFAULT_OAUTH_FOLDER_TEMPLATE("%s-%s-%s"),

    DATASOURCE_POLLING_INTERVAL("1d"),

    CONTACTS_IMAGE_BUFFER_SIZE("2048"),

    PROPERTIES_NAME_APPLICATION("application");

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
    private OAuth2Constants(String constant) {
        this.constant = constant;
    }
}
