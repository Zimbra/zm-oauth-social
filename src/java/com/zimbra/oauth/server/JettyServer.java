package com.zimbra.oauth.server;

import java.util.EnumSet;

import javax.servlet.DispatcherType;

import org.apache.commons.lang.StringUtils;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.InvalidClientException;
import com.zimbra.oauth.filters.OAuthExceptionFilter;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

public class JettyServer {

	/**
	 * Jetty server instance.
	 */
	protected Server server;

	/**
	 * Application config (non-client specific).
	 */
	protected Configuration config;

	/**
	 * Application main.
	 *
	 * @param args Program input
	 */
	public static void main(String[] args) {
		final JettyServer jettyServer = new JettyServer();
		jettyServer.setup();
		ZimbraLog.extensions.info("Starting jetty server.");
		jettyServer.run();
	}

	/**
	 * JettyServer constructor.<br>
	 * Initializes the jetty server with config.
	 */
	public JettyServer() {
		// load default config
		try {
			config = Configuration.getDefaultConfiguration();
		} catch (InvalidClientException | ConfigurationException e) {
			e.printStackTrace();
		}

		// setup ZimbraLog
		ZimbraLog.toolSetupLog4jConsole(config.getString(OAuth2Constants.LC_OAUTH_LOG_LEVEL, OAuth2Constants.DEFAULT_LOG_LEVEL), true, false);
	}

	/**
	 * Configure Jetty server.
	 */
	protected void setup() {
		final ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath(StringUtils.defaultIfEmpty(config.getString(OAuth2Constants.LC_OAUTH_SERVER_CONTEXT_PATH), OAuth2Constants.DEFAULT_SERVER_CONTEXT_PATH));
		context.addFilter(OAuthExceptionFilter.class, OAuth2Constants.DEFAULT_SERVER_CONTEXT_PATH, EnumSet.of(DispatcherType.REQUEST));
		final ServletHolder jerseyServlet = context.addServlet(org.glassfish.jersey.servlet.ServletContainer.class, OAuth2Constants.DEFAULT_SERVER_CONTEXT_PATH);
		jerseyServlet.setInitOrder(0);
		jerseyServlet.setInitParameter("jersey.config.server.provider.packages", "com.zimbra.oauth, com.fasterxml.jackson.jaxrs.json");

		server = new Server(config.getInteger(OAuth2Constants.LC_OAUTH_SERVER_PORT, OAuth2Constants.DEFAULT_SERVER_PORT));
		server.setHandler(context);
	}

	/**
	 * Runs the configured jetty server.
	 */
	protected void run() {
		try {
			server.start();
			server.join();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
