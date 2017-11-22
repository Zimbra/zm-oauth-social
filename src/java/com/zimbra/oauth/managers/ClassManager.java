package com.zimbra.oauth.managers;

import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.InvalidClientException;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.OAuth2Constants;

public class ClassManager {

	/**
	 * Cache of handler instances by client name.
	 */
	protected static final Map<String, IOAuth2Handler> handlersCache = Collections.synchronizedMap(new HashMap<String, IOAuth2Handler>());

	/**
	 * Loads an IOAuth2Handler for a given client.<br>
	 * Checks for cached instance before instantiating.
	 *
	 * @param client The client to get a handler for (yahoo, gmail, etc)
	 * @return An IOAuthHandler instance
	 * @throws ConfigurationException
	 */
	public static IOAuth2Handler getHandler(String client) throws ConfigurationException, InvalidClientException {
		// check the cache for a matching handler
		IOAuth2Handler handler = handlersCache.get(client);

		// if no cached handler, try to build then cache one
		if (handler == null) {
			// synchronize and re-fetch from cache to prevent duplicates
			synchronized(handlersCache) {
				handler = handlersCache.get(client);
				if (handler == null) {
					try {
						// load a config file
						final Configuration config = Configuration.buildConfiguration(client);

						// load the handler class
						final String className = config.getString(OAuth2Constants.PROPERTIES_HANDLER_PREFIX + client);
						final Class<?> daoClass = Class.forName(className);
						handler = (IOAuth2Handler) daoClass.getConstructor(Configuration.class).newInstance(config);

						// cache the new handler
						handlersCache.put(client, handler);
					} catch (ConfigurationException | InvalidClientException e) {
						ZimbraLog.extensions.debug("There was an issue loading the configuration for the client.", e);
						throw e;
					} catch (final ClassNotFoundException e) {
						ZimbraLog.extensions.error("The specified client is not supported: " + client, e);
						throw new InvalidClientException("The specified client is not supported: " + client, e);
					} catch (InstantiationException | IllegalAccessException | IllegalArgumentException
						| InvocationTargetException | NoSuchMethodException | SecurityException e) {
						ZimbraLog.extensions.error("There was an issue instantiating the oauth2 handler class for client: " + client, e);
						throw new ConfigurationException("There was an issue instantiating the oauth2 handler class for client: " + client, e);
					}
				}
			}
		}
		return handler;
	}
}
