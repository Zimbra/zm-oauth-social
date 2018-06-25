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
package com.zimbra.oauth.managers;

import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.handlers.IOAuth2Handler;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;
import com.zimbra.oauth.utilities.OAuth2Constants;

/**
 * The ClassManager class.<br>
 * Maps a client to the client specific handler class.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.managers
 * @copyright Copyright © 2018
 */
public class ClassManager {

    /**
     * Cache of handler instances by client name.
     */
    protected static final Map<String, IOAuth2Handler> handlersCache = Collections
        .synchronizedMap(new HashMap<String, IOAuth2Handler>());

    /**
     * Loads an IOAuth2Handler for a given client.<br>
     * Checks for cached instance before instantiating.
     *
     * @param client The client to get a handler for (yahoo, google, etc)
     * @return An IOAuthHandler instance
     * @throws ServiceException If there are issues
     */
    public static IOAuth2Handler getHandler(String client)
        throws ServiceException {
        // check the cache for a matching handler
        IOAuth2Handler handler = handlersCache.get(client);

        // if no cached handler, try to build then cache one
        if (handler == null) {
            // synchronize and re-fetch from cache to prevent duplicates
            synchronized (handlersCache) {
                handler = handlersCache.get(client);
                if (handler == null) {
                    try {
                        // load a config file
                        final Configuration config = LdapConfiguration.buildConfiguration(client);

                        // load the handler class
                        final Class<?> daoClass = Class.forName(
                            config.getString(OAuth2Constants.LC_HANDLER_CLASS_PREFIX.getValue() + client));
                        handler = (IOAuth2Handler) daoClass.getConstructor(Configuration.class)
                            .newInstance(config);

                        // cache the new handler
                        handlersCache.put(client, handler);
                    } catch (final ServiceException e) {
                        ZimbraLog.extensions.debug(
                            "There was an issue loading the configuration for the client.", e);
                        throw e;
                    } catch (final ClassNotFoundException e) {
                        ZimbraLog.extensions
                            .warnQuietly("The specified client is not supported: " + client, e);
                        throw ServiceException.UNSUPPORTED();
                    } catch (InstantiationException | IllegalAccessException
                        | IllegalArgumentException | InvocationTargetException
                        | NoSuchMethodException | SecurityException e) {
                        ZimbraLog.extensions.errorQuietly(
                            "There was an issue instantiating the oauth2 handler class for client: "
                                + client,
                            e);
                        throw ServiceException.FAILURE(
                            "There was an issue instantiating the oauth2 handler class for client: "
                                + client,
                            e);
                    }
                }
            }
        }
        return handler;
    }
}
