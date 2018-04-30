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

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

/**
 * The ConfigurationException class.<br>
 * Exception class to indicate exceptions with configurations.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.exceptions
 * @copyright Copyright © 2018
 */
public class ConfigurationException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor.
	 *
	 * @param message An error message
	 */
	public ConfigurationException(String message) {
		this(message, null);
	}

	/**
	 * Constructor.
	 *
	 * @param throwable A throwable object
	 */
	public ConfigurationException(Throwable throwable) {
		this(null, throwable);
	}

	/**
	 * Constructor.
	 *
	 * @param message An error message
	 * @param throwable A throwable object
	 */
	public ConfigurationException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.CONFIGURATION_ERROR);
		setStatus(Status.INTERNAL_SERVER_ERROR);
	}

}
