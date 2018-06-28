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
package com.zimbra.oauth.utilities;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;

/**
 * The Configuration class for this project.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class Configuration {

    /**
     * Map storing configurations per client.
     */
    protected static Map<String, Configuration> configCache = Collections
        .synchronizedMap(new HashMap<String, Configuration>());

    /**
     * The config name.
     */
    private String clientId = null;

    /**
     * Constructor.
     *
     * @param clientId A client id
     */
    protected Configuration(String clientId) {
        setClientId(clientId);
    }

    /**
     * Set the client id.
     *
     * @param clientId A client id
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Get the client id.
     *
     * @return A client id
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Get the associated value with the key.
     *
     * @param key A key to lookup
     * @return A value for a given key
     */
    public String getString(String key) {
        return getString(key, null);
    }

    /**
     * Get the associated value with the key or the default value.
     *
     * @param key A key to lookup
     * @param defaultValue A default value to use if value for key is empty
     * @return A value for the given key or the default value
     */
    public String getString(String key, String defaultValue) {
        return StringUtils.defaultIfEmpty(LC.get(key), defaultValue);
    }

    /**
     *
     * @param key A key to lookup
     * @param appName the social client name
     * @param acct the user account
     * @return A value for the given key or the default value
     */
    public String getString(String key, String appName, Account acct) {
        return StringUtils.defaultIfEmpty(LC.get(key), null);
    }

    /**
     * Gets integer value from the local configuration for the given key or the
     * default value.
     *
     * @param key A key to lookup
     * @param defaultValue A default value to use if value for key is empty
     * @return A value for the given key or the default value
     */
    public Integer getInt(String key, Integer defaultValue) {
        final String stringValue = LC.get(key);
        Integer value = defaultValue;
        if (stringValue != null) {
            try {
                value = Integer.parseInt(stringValue);
            } catch (final NumberFormatException e) {
                ZimbraLog.extensions
                    .debug("Cannot parse integer from configured LC value for key: '" + key + "'.");
            }
        }
        return value;
    }

    /**
     * Creates a default configuration (non-client specific).<br>
     * Does not cache the configuration object.
     *
     * @return The default Configuration object
     */
    public static Configuration getDefaultConfiguration() {
        return new Configuration(OAuth2Constants.PROPERTIES_NAME_APPLICATION.getValue());
    }

    /**
     * Determines if a specified name is a valid client for this service.<br>
     * A client is valid if localconfig contains a specified handler class for
     * the client.<br>
     * Note this does not necessarily mean the class exists on the classpath.
     *
     * @param name The client name
     * @return True if the client name is known by the service
     */
    protected static boolean isValidClient(String name) {
        return !StringUtils.isEmpty(LC.get(OAuth2ConfigConstants.LC_HANDLER_CLASS_PREFIX.getValue() + name));
    }

    /**
     * Loads a single configuration by name (no extension).<br>
     * Creates a Configuration and caches the Configuration.
     *
     * @param name Name of the client
     * @return Configuration object
     * @throws ServiceException If there are issues
     */
    public static Configuration buildConfiguration(String name) throws ServiceException {
        Configuration config = null;

        // try to find config in cache
        if (name != null) {
            config = configCache.get(name);
        }

        // if the config is empty, try to load it
        if (config == null) {
            // validate the client
            if (!isValidClient(name)) {
                throw ServiceException.UNSUPPORTED();
            }
            config = new Configuration(name);
        }
        configCache.put(name, config);
        return config;
    }
}
