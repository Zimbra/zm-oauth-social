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
 * @author zimbra
 *
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
     * 
     */
    @Override
    public String getString(String key) {
        
        String appName = getAppName(key);
        return getConfig(key, appName);
    }

    /**
     * @param oauthClientId
     * @param appName
     * @return
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
                    // {redirectURI}:{consumer-app-name}
                    for (String consumer : registeredOAuth2RedirectUrls) {
                        String s[] = consumer.split(":");
                        if (s.length == 2 && s[1].equals(appName)) {
                            return s[0];
                        }
                    }
                }
            } else if (key.endsWith(OAuth2Constants.OAUTH_SCOPE)) {
                String[] registeredOAuth2APIScope = Provisioning.getInstance().getConfig()
                    .getMultiAttr(Provisioning.A_zimbraOAuthConsumerAPIScope);

                if (registeredOAuth2APIScope != null && registeredOAuth2APIScope.length != 0) {
                    for (String consumer : registeredOAuth2APIScope) {
                        String s[] = consumer.split(":");
                        if (s.length == 2 && s[1].equals(appName)) {
                            value = s[0];
                            break;
                        }
                    }
                }
            }
        } catch (ServiceException e) {
            ZimbraLog.extensions.info("Error fetching configuration : %s for : %s", key, appName);
            ZimbraLog.extensions.debug(e);
        }
        return value;
        
    }


    /**
     * Return the name of the client app, based on the key.
     * @param key the client related key(zm_oauth_yahoo_client_id,zm_oauth_google_client_secret,
     * zm_oauth_outlook_client_redirect_uri
     * @return the client app name
     */
    private String getAppName(String key) {
        
        if (key.contains(OAuth2Constants.APPNAME_YAHOO)) {
            return OAuth2Constants.APPNAME_YAHOO;
        } else if (key.contains(OAuth2Constants.APPNAME_GOOGLE)) {
            return OAuth2Constants.APPNAME_GOOGLE;
        } else if (key.contains(OAuth2Constants.APPNAME_FACEBOOK)) {
            return OAuth2Constants.APPNAME_FACEBOOK;
        }  else if (key.contains(OAuth2Constants.APPNAME_OUTLOOK)) {
            return OAuth2Constants.APPNAME_OUTLOOK;
        } else {
            ZimbraLog.extensions.info("Received request for unsupported app config: %s", key);
            return null;
        }
    }    

}
