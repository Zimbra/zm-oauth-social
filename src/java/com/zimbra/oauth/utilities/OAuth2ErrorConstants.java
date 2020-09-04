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
 * The OAuth2ErrorConstants class.<br>
 * OAuth2HttpConstants contains error-related constants used in the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public enum OAuth2ErrorConstants {

    ERROR_ACCESS_DENIED("access_denied"),
    ERROR_INVALID_AUTH_CODE("invalid_auth_code"),
    ERROR_INVALID_CLIENT("invalid_client"),
    ERROR_INVALID_ZM_AUTH_CODE("invalid_zm_auth_code"),
    ERROR_INVALID_ZM_AUTH_CODE_MSG("Invalid or missing Zimbra session."),
    ERROR_AUTHENTICATION_ERROR("authentication_error"),
    ERROR_UNHANDLED_ERROR("unhandled_error"),
    ERROR_TYPE_MISSING("missing_type"),
    ERROR_PARAM_MISSING("missing_param"),
    ERROR_REFRESH_UNSUPPORTED("refresh_unsupported"),
    ERROR_REFRESH_UNSUPPORTED_MSG("Refresh is not supported for this client."),
    ERROR_CONFIGURATION_MISSING("missing_configuration"),
    ERROR_CONFIGURATION_MISSING_MSG("OAuth is not properly configured for this client."),
    ERROR_INVALID_PROXY_TARGET("invalid_proxy_target"),
    ERROR_INVALID_PROXY_CLIENT("invalid_proxy_client"),
    ERROR_INVALID_PROXY_RESPONSE("invalid_proxy_response"),
    ERROR_INVALID_CLIENT_TYPES("invalid_client_and_types"),
    ERROR_INVALID_CLIENT_TYPES_MSG("Client and types combination not supported.");

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
    private OAuth2ErrorConstants(String constant) {
        this.constant = constant;
    }
}
