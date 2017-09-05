package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UserForbiddenException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UserForbiddenException(String message) {
		super(message);
		error = OAuth2Error.USER_FORBIDDEN_ERROR;
		status = Status.FORBIDDEN;
	}

	public UserForbiddenException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public UserForbiddenException(Throwable throwable) {
		super(throwable);
	}

}
