package com.zimbra.oauth.utilities;

import java.io.FileNotFoundException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;

import com.zimbra.oauth.exceptions.ConfigurationException;
import com.zimbra.oauth.exceptions.InvalidClientException;

public class Configuration extends CompositeConfiguration {

	/**
	 * Map storing configurations per client.
	 */
	private static Map<String, Configuration> configCache = Collections.synchronizedMap(new HashMap<String, Configuration>());

	/**
	 * Map storing properties configurations.
	 */
	private static Map<String, PropertiesConfiguration> propertiesCache = Collections.synchronizedMap(new HashMap<String, PropertiesConfiguration>());

	/**
	 * The config name.
	 */
	private String clientId = null;

	protected Configuration(String clientId) throws InvalidClientException, ConfigurationException {
		setClientId(clientId);
		// every config should also have the class properties
		addApplicationProperties();
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientId() {
		return clientId;
	}

	/**
	 * Adds the application properties to this Configuration object.
	 *
	 * @throws InvalidClientException If the file does not exist
	 * @throws ConfigurationException If there are issues loading the file
	 */
	protected void addApplicationProperties() throws InvalidClientException, ConfigurationException {
		addConfiguration(getPropertiesConfiguration(OAuth2Constants.PROPERTIES_NAME_APPLICATION));
	}

	/**
	 * Loads the default configuration (non-client specific).<br>
	 * Does not cache the configuration object.
	 *
	 * @return The default Configuration object
	 * @throws InvalidClientException If the file does not exist
	 * @throws ConfigurationException If there are issues loading the file
	 */
	public static Configuration getDefaultConfiguration() throws InvalidClientException, ConfigurationException {
		final Configuration config = new Configuration(OAuth2Constants.PROPERTIES_NAME_APPLICATION);
		config.setDelimiterParsingDisabled(true);
		return config;
	}

	/**
	 * Loads a single properties file by name (no extension).<br>
	 * Creates a Configuration, attaches requires sub-properties files and caches the Configuration.
	 *
	 * @param name Name of the config file (no extension)
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
			config.setDelimiterParsingDisabled(true);
			config.addConfiguration(getPropertiesConfiguration(name));
		}
		configCache.put(name, config);
		return config;
	}

	/**
	 * Loads the properties for a given file name.<br>
	 * Caches the loaded properties.
	 *
	 * @param name Name of the config file (no extension)
	 * @return Properties from the config file
	 * @throws InvalidClientException If there are issues loading the file
	 * @throws ConfigurationException If the file does not exist
	 */
	protected static PropertiesConfiguration getPropertiesConfiguration(String name) throws InvalidClientException, ConfigurationException {
		PropertiesConfiguration propertiesConfig = propertiesCache.get(name);
		// if not in cache, load it then cache it
		if (propertiesConfig == null) {
			final String propertiesFilename = name + ".properties";
			propertiesConfig = new PropertiesConfiguration();
			propertiesConfig.setDelimiterParsingDisabled(true);
			propertiesConfig.setReloadingStrategy(new FileChangedReloadingStrategy());
			try {
				propertiesConfig.load(propertiesFilename);
			} catch (final org.apache.commons.configuration.ConfigurationException e) {
				if (!(e.getCause() instanceof FileNotFoundException)) {
					throw new InvalidClientException(e.getMessage());
				} else {
					throw new ConfigurationException(e);
				}
			}
			propertiesCache.put(name, propertiesConfig);
		}
		return propertiesConfig;
	}
}
