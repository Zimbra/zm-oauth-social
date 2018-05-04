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
 * The OAuth2Error class.<br>
 * OAuth2Error contains error codes for the project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public enum OAuth2Error {

    GENERIC_OAUTH_ERROR,
    CONFIGURATION_ERROR,
    INVALID_OPERATION_ERROR,
    USER_UNAUTHORIZED_ERROR,
    INVALID_RESPONSE_ERROR,
    USER_FORBIDDEN_ERROR,
    UNREACHABLE_HOST_ERROR,
    SERVICE_NOT_AVAILABLE_ERROR,
    INVALID_CLIENT_ERROR

}
