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

import com.zimbra.oauth.utilities.OAuth2Error;

/**
 * The ErrorObject class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.models
 * @copyright Copyright © 2018
 */
@XmlRootElement
public class ErrorObject {

	/**
	 * Error message.
	 */
	protected String errorMessage;

	/**
	 * Error code.
	 */
	protected OAuth2Error errorCode;

	/**
	 * Constructor.
	 *
	 * @param code An error code
	 * @param message An error message
	 */
	public ErrorObject(OAuth2Error code, String message) {
		errorCode = code;
		errorMessage = message;
	}

	/**
	 * Get the error message.
	 *
	 * @return errorMessage The error message
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	/**
	 * Set the error message.
	 *
	 * @param errorMessage An error message
	 */
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	/**
	 * Get the error code.
	 *
	 * @return errorCode An error code
	 */
	public OAuth2Error getErrorCode() {
		return errorCode;
	}

	/**
	 * Set the error code.
	 *
	 * @param errorCode An error code
	 */
	public void setErrorCode(OAuth2Error errorCode) {
		this.errorCode = errorCode;
	}

}
