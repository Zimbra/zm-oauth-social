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

import javax.ws.rs.ext.Provider;

import com.zimbra.oauth.utilities.OAuth2Error;

/**
 * The GenericOAuthException class.<br>
 * Use as a base class for other exceptions.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.exceptions
 * @copyright Copyright © 2018
 */
@Provider
public class GenericOAuthException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * Error code of this exception.
     */
    protected OAuth2Error error = OAuth2Error.GENERIC_OAUTH_ERROR;

    /**
     * Constructor.
     */
    public GenericOAuthException() {
        super();
    }

    /**
     * Constructor.
     *
     * @param message An error message
     */
    public GenericOAuthException(String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param message An error message
     * @param throwable A throwable object
     */
    public GenericOAuthException(String message, Throwable throwable) {
        super(message, throwable);
    }

    /**
     * Constructor.
     *
     * @param throwable A throwable object
     */
    public GenericOAuthException(Throwable throwable) {
        super(throwable);
    }

    /**
     * Get OAuth2Error error object.
     *
     * @return error The error object
     */
    public OAuth2Error getError() {
        return error;
    }

    /**
     * Set the OAuth2Error error object.
     *
     * @param error An error object
     */
    public void setError(OAuth2Error error) {
        this.error = error;
    }

}
