package com.zimbra.oauth.resources;

import javax.ws.rs.CookieParam;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.utilities.OAuth2HandlerUtilities;

@Path("oauth2")
public class OAuth2Resource {

	/**
	 * Redirects to the client's authorize endpoint.
	 *
	 * @param client The client to redirect to (yahoo, gmail, outlook, etc)
	 * @param relay The location to direct the user after authenticating
	 * @return HTTP Response 303
	 * @throws GenericOAuthException
	 */
	@GET
	@Path("authorize/{client}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authorize(@PathParam("client") String client, @QueryParam("relay") String relay) throws GenericOAuthException {
		return OAuth2HandlerUtilities.authorize(client, relay);
	}

	/**
	 * Authenticates a user with the endpoint and stores credentials in ephemeral-store.<br>
	 * Errors will be contained in query parameters `error`, and `error_msg` (if extra details exist).
	 *
	 * @param client The client to redirect to (yahoo, gmail, outlook, etc)
	 * @param code Code from authorizing endpoint
	 * @param error Errors from authorizing endpoint
	 * @param relay The location to direct the user after authenticating
	 * @return HTTP Response 303
	 * @throws GenericOAuthException
	 */
	@GET
	@Path("authenticate/{client}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(@PathParam("client") String client, @QueryParam("code") String code,
		@QueryParam("error") String error, @QueryParam("state") String relay, @CookieParam("ZM_AUTH_TOKEN") String zmAuthToken) throws GenericOAuthException {
		return OAuth2HandlerUtilities.authenticate(client, code, error, relay, zmAuthToken);
	}

	@POST
	@Path("subscribe/{client}/{username}/{subscription}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response subscribe(@PathParam("client") String client, @PathParam("username") String username,
		@PathParam("subscription") String subscription) throws GenericOAuthException {
		return OAuth2HandlerUtilities.subscribe(client, username, subscription);
	}

	@DELETE
	@Path("unsubscribe/{client}/{username}/{subscription}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response unsubscribe(@PathParam("client") String client, @PathParam("username") String username,
		@PathParam("subscription") String subscription) throws GenericOAuthException {
		return OAuth2HandlerUtilities.unsubscribe(client, username, subscription);
	}

	@POST
	@Path("refresh/{client}/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response refresh(@PathParam("client") String client, @PathParam("username") String username) throws GenericOAuthException {
		return OAuth2HandlerUtilities.refresh(client, username);
	}
}
