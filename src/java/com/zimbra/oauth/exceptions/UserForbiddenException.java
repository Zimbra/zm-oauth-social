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
package com.zimbra.oauth.exceptions;

import com.zimbra.oauth.utilities.OAuth2Error;

/**
 * The UserForbiddenException class.<br>
 * Indicates that the requesting user has insufficient privileges to perform a
 * requested action.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.exceptions
 * @copyright Copyright © 2018
 */
public class UserForbiddenException extends GenericOAuthException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     *
     * @param message An error message
     */
    public UserForbiddenException(String message) {
        this(message, null);
    }

    /**
     * Constructor.
     *
     * @param throwable A throwable object
     */
    public UserForbiddenException(Throwable throwable) {
        this(null, throwable);
    }

    /**
     * Constructor.
     *
     * @param message An error message
     * @param throwable A throwable object
     */
    public UserForbiddenException(String message, Throwable throwable) {
        super(message, throwable);
        setError(OAuth2Error.USER_FORBIDDEN_ERROR);
    }

}
