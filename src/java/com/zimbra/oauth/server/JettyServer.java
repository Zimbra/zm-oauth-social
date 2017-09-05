package com.zimbra.oauth.server;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public class JettyServer {

	protected Server server;

	public static void main(String[] args) {
//		ZimbraLog.extensions.info("Starting jetty server.");
		final JettyServer jettyServer = new JettyServer();
		jettyServer.run();
	}

	public JettyServer() {
		final ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
		context.setContextPath("/");

		server = new Server(8080);
		server.setHandler(context);

		final ServletHolder jerseyServlet = context.addServlet(org.glassfish.jersey.servlet.ServletContainer.class, "/*");
		jerseyServlet.setInitOrder(0);
		jerseyServlet.setInitParameter("jersey.config.server.provider.packages", "com.zimbra.oauth, com.fasterxml.jackson.jaxrs.json");
	}

	protected void run() {
		try {
			server.start();
			server.join();
		} catch (final Exception e) {
			e.printStackTrace();
		}
	}
}
