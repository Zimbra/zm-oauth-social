package com.zimbra.oauth.token.utilities;

import org.apache.commons.lang.StringUtils;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Provisioning;

/**
 * @author zimbra
 *
 */
public class LdapOauthHelper {

    public  static String[] loadConfiguration(Account acct, String key, String appName) {
        String [] values = null;
        ZimbraLog.extensions.trace("Loading configuration: %s for: %s", key, acct.getName());
        try {
            values = Provisioning.getInstance().getDomain(acct).getMultiAttr(key);
            final String temp = StringUtils.join(values);
            if (values == null || values.length == 0 || !temp.contains(appName)) {
                ZimbraLog.extensions.trace("Config:%s does not exist at domain level", key);
                values = Provisioning.getInstance().getConfig()
                    .getMultiAttr(key);
            }
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration : %s for : %s", key, acct.getName());
            ZimbraLog.extensions.debug(e);
        }
        ZimbraLog.extensions.debug("Configuration is: %s", StringUtils.join(values));
        return values;
    }



}
