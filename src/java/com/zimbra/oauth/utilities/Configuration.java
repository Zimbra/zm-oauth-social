package com.zimbra.oauth.utilities;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import com.zimbra.common.localconfig.LC;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.InvalidClientException;

public class Configuration {

	/**
	 * Map storing configurations per client.
	 */
	private static Map<String, Configuration> configCache = Collections.synchronizedMap(new HashMap<String, Configuration>());

	/**
	 * The config name.
	 */
	private String clientId = null;

	protected Configuration(String clientId) {
		setClientId(clientId);
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientId() {
		return clientId;
	}

	public String getString(String key) {
		return getString(key, null);
	}

	public String getString(String key, String defaultValue) {
		return StringUtils.defaultIfEmpty(LC.get(key), defaultValue);
	}

	public Integer getInt(String key, Integer defaultValue) {
		final String stringValue = LC.get(key);
		Integer value = defaultValue;
		if (stringValue != null) {
			try
			{
				value = Integer.parseInt(stringValue);
			}
			catch (final NumberFormatException e) {
				ZimbraLog.extensions.debug("Cannot parse integer from configured LC value for key: '" + key + "'.");
			}
		}
		return value;
	}

	/**
	 * Creates a default configuration (non-client specific).<br>
	 * Does not cache the configuration object.
	 *
	 * @return The default Configuration object
	 * @throws InvalidClientException If the file does not exist
	 * @throws ConfigurationException If there are issues loading the file
	 */
	public static Configuration getDefaultConfiguration() throws InvalidClientException, ConfigurationException {
		return new Configuration(OAuth2Constants.PROPERTIES_NAME_APPLICATION);
	}

	/**
	 * Loads a single configuration by name (no extension).<br>
	 * Creates a Configuration and caches the Configuration.
	 *
	 * @param name Name of the client
	 * @return Configuration object
	 * @throws ConfigurationException If there are issues loading the file
	 * @throws InvalidClientException If the file does not exist
	 */
	public static Configuration buildConfiguration(String name) throws ConfigurationException, InvalidClientException {
		Configuration config = null;

		// try to find config in cache
		if (name != null) {
			config = configCache.get(name);
		}

		// if the config is empty, try to load it
		if (config == null) {
			config = new Configuration(name);
		}
		configCache.put(name, config);
		return config;
	}
}
