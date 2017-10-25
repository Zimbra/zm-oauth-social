package com.zimbra.oauth.exceptions;

import javax.ws.rs.core.Response.Status;

import com.zimbra.oauth.utilities.OAuth2Error;

public class UserForbiddenException extends GenericOAuthException {

	private static final long serialVersionUID = 1L;

	public UserForbiddenException(String message) {
		this(message, null);
	}

	public UserForbiddenException(Throwable throwable) {
		this(null, throwable);
	}

	public UserForbiddenException(String message, Throwable throwable) {
		super(message, throwable);
		setError(OAuth2Error.USER_FORBIDDEN_ERROR);
		setStatus(Status.FORBIDDEN);
	}

}
