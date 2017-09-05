package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UserUnauthorizedException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UserUnauthorizedException(String message) {
		super(message);
		error = OAuth2Error.USER_UNAUTHORIZED_ERROR;
		status = Status.UNAUTHORIZED;
	}

	public UserUnauthorizedException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public UserUnauthorizedException(Throwable throwable) {
		super(throwable);
	}

}
