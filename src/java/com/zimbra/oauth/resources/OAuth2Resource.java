package com.zimbra.oauth.resources;

import javax.ws.rs.CookieParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.zimbra.oauth.exceptions.GenericOAuthException;
import com.zimbra.oauth.utilities.OAuth2ResourceUtilities;

@Path("oauth2")
public class OAuth2Resource {

	/**
	 * Redirects to the client's authorize endpoint.
	 *
	 * @param client The client to redirect to for authorization (yahoo, google, outlook, etc)
	 * @param relay The location to direct the user after authenticating
	 * @return HTTP Response 303
	 * @responseMessage 303 Client authorization location
	 * @throws GenericOAuthException If there are unhandled issues determining the authorize location
	 */
	@GET
	@Path("authorize/{client}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authorize(@PathParam("client") String client, @QueryParam("relay") String relay) throws GenericOAuthException {
		return OAuth2ResourceUtilities.authorize(client, relay);
	}

	/**
	 * Authenticates a user with the endpoint and stores credentials in ephemeral-store.<br>
	 * Errors will be contained in query parameters `error`, and `error_msg` (if extra details exist).
	 *
	 * @param client The client used to authenticate (yahoo, google, outlook, etc)
	 * @param code Code from authorizing endpoint
	 * @param error Errors from authorizing endpoint
	 * @param relay The location to direct the user after authenticating
	 * @return HTTP Response 303
	 * @responseMessage 303 Configured location
	 * @throws GenericOAuthException If there are unhandled issues authenticating
	 */
	@GET
	@Path("authenticate/{client}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response authenticate(@PathParam("client") String client, @QueryParam("code") String code,
		@QueryParam("error") String error, @QueryParam("state") String relay, @CookieParam("ZM_AUTH_TOKEN") String zmAuthToken) throws GenericOAuthException {
		return OAuth2ResourceUtilities.authenticate(client, code, error, relay, zmAuthToken);
	}

	@POST
	@Path("refresh/{client}/{username}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response refresh(@PathParam("client") String client, @PathParam("username") String username, @CookieParam("ZM_AUTH_TOKEN") String zmAuthToken) throws GenericOAuthException {
		return OAuth2ResourceUtilities.refresh(client, username, zmAuthToken);
	}
}
