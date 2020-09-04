package com.zimbra.oauth.token.utilities;

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

/**
 * @author zimbra
 *
 */
public enum OAuth2TokenConstants {

    NEXTCLOUD_CLIENT_NAME("nextcloud"),
    NEXTCLOUD_AUTHENTICATE_URI("/apps/oauth2/api/v1/token"),
    NEXTCLOUD_HOST_NEXTCLOUD("nextcloud_dummy_host");


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
    private OAuth2TokenConstants(String constant) {
        this.constant = constant;
    }
}
