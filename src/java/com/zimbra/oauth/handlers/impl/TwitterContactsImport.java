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
package com.zimbra.oauth.handlers.impl;

import java.util.List;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.account.DataSource.DataImport;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterOAuth2Constants;
import com.zimbra.oauth.utilities.Configuration;
import com.zimbra.oauth.utilities.LdapConfiguration;

/**
 * The TwitterContactsImport class.<br>
 * Used to sync contacts from the Twitter social service.<br>
 * Based on the original YahooContactsImport class by @author Greg Solovyev.
 *
 * @author Zimbra API Team
 * @package com.zimbra.oauth.handlers.impl
 * @copyright Copyright © 2018
 */
public class TwitterContactsImport implements DataImport {

    /**
     * The datasource under import.
     */
    private final DataSource mDataSource;

    /**
     * Configuration wrapper.
     */
    private Configuration config;

    /**
     * Constructor.
     *
     * @param datasource The datasource to set
     */
    public TwitterContactsImport(DataSource datasource) {
        mDataSource = datasource;
        try {
            config = LdapConfiguration.buildConfiguration(TwitterOAuth2Constants.CLIENT_NAME.getValue());
        } catch (final ServiceException e) {
            ZimbraLog.extensions.info("Error loading configuration for twitter: %s", e.getMessage());
            ZimbraLog.extensions.debug(e);
        }
    }

    @Override
    public void test() throws ServiceException {
        // TODO
    }

    @Override
    public void importData(List<Integer> folderIds, boolean fullSync) throws ServiceException {
        // TODO
    }

}
