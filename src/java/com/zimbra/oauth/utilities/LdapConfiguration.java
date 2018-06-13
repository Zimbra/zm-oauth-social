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

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Provisioning;

/**
 * The Configuration class for this project for loading attributes from LDAP
 * @author Zimbra API Team
 * @package com.zimbra.oauth.utilities
 * @copyright Copyright © 2018
 */
public class LdapConfiguration extends Configuration {

    
    /**
     * @param appName
     * @throws ServiceException
     */
    protected LdapConfiguration(String appName) {
        super(appName);    
    }
    
    
    /**
     * Get the associated value with the key.
     *
     * @param key A key to lookup
     * @return A value for a given key
     */
    @Override
    public String getString(String key) {
        
        String appName = this.getClientId();
        return getConfig(key, appName);
    }

    /**
     * @param oauth related config key
     * @param appName client app name
     * @return value for the associated key
     */
    public String getConfig(String key, String appName) {

        String value = null;
        try {
           if (key.endsWith(OAuth2Constants.OAUTH_CLIENT_ID)) {
                String[] registeredOAuth2Clients = Provisioning.getInstance().getConfig()
                    .getMultiAttr(Provisioning.A_zimbraOAuthConsumerCredentials);
                if (registeredOAuth2Clients != null && registeredOAuth2Clients.length != 0) {
                    // {consumer-id}:{secret}:{consumer-app-name}
                    for (String consumer : registeredOAuth2Clients) {
                        String s[] = consumer.split(":");
                        if (s.length == 3 && s[2].equals(appName)) {
                            value = s[0];
                            break;
                        }
                    }
                }
            } else if (key.endsWith(OAuth2Constants.OAUTH_CLIENT_SECRET)) {
                String[] registeredOAuth2Clients = Provisioning.getInstance().getConfig()
                    .getMultiAttr(Provisioning.A_zimbraOAuthConsumerCredentials);
                if (registeredOAuth2Clients != null && registeredOAuth2Clients.length != 0) {
                    // {consumer-id}:{secret}:{consumer-app-name}
                    for (String consumer : registeredOAuth2Clients) {
                        String s[] = consumer.split(":");
                        if (s.length == 3 && s[2].equals(appName)) {
                            value = s[1];
                            break;
                        }
                    }
                }
            } else if (key.endsWith(OAuth2Constants.OAUTH_CLIENT_REDIRECT_URI)) {
                String[] registeredOAuth2RedirectUrls = Provisioning.getInstance().getConfig()
                    .getMultiAttr(Provisioning.A_zimbraOAuthConsumerRedirectUri);
                if (registeredOAuth2RedirectUrls != null
                    && registeredOAuth2RedirectUrls.length != 0) {
                    // {redirectURI}:{consumer-app-name} (the redirect uri can contain ":")
                    for (String consumer : registeredOAuth2RedirectUrls) {
                        int index = consumer.lastIndexOf(':');
                        if (index != -1) {
                            String temp = consumer.substring(index+1);
                            if (temp.equals(appName)) {
                                value = consumer.substring(0, index);
                                break;
                            }
                        }
                    }
                }
            } else if (key.endsWith(OAuth2Constants.OAUTH_SCOPE)) {
                String[] registeredOAuth2APIScope = Provisioning.getInstance().getConfig()
                    .getMultiAttr(Provisioning.A_zimbraOAuthConsumerAPIScope);

                if (registeredOAuth2APIScope != null && registeredOAuth2APIScope.length != 0) {
                    for (String scope : registeredOAuth2APIScope) {
                        int index = scope.lastIndexOf(':');
                        if (index != -1) {
                            String temp = scope.substring(index+1);
                            if (temp.equals(appName)) {
                                value = scope.substring(0, index);
                                break;
                            }
                        }
                    }
                }
            } else {
                value = getString(key, null);
            }
        } catch (ServiceException e) {
            ZimbraLog.extensions.info("Error fetching configuration : %s for : %s", key, appName);
            ZimbraLog.extensions.debug(e);
        }
        if (key.endsWith(OAuth2Constants.OAUTH_CLIENT_SECRET)) {
            ZimbraLog.extensions.trace("Requested : %s  and value is: %s ", key, "****");
        } else {
            ZimbraLog.extensions.trace("Requested : %s  and value is: %s ", key, value);
        }
        return value;
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
           config = new LdapConfiguration(name);
       }
       configCache.put(name, config);
       return config;
   }

}
