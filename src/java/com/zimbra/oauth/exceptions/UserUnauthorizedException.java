package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UserUnauthorizedException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UserUnauthorizedException(String message) {
		this(message, null);
	}

	public UserUnauthorizedException(Throwable throwable) {
		this(null, throwable);
	}

	public UserUnauthorizedException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.USER_UNAUTHORIZED_ERROR);
		setStatus(Status.UNAUTHORIZED);
	}

}
