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

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.matches;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.fasterxml.jackson.databind.JsonNode;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.oauth.handlers.impl.TwitterContactsImport.TwitterContactsUtil;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterAuthorizationBuilder;
import com.zimbra.oauth.handlers.impl.TwitterOAuth2Handler.TwitterContactConstants;
import com.zimbra.oauth.utilities.Configuration;

/**
 * Test class for {@link TwitterContactsImport}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSource.class, TwitterContactsImport.class, TwitterContactsUtil.class })
public class TwitterContactsImportTest {

    /**
     * Class under test.
     */
    protected TwitterContactsImport importer;

    /**
     * Auth header for testing.
     */
    protected final String authHeader = "test-auth-header";

    /**
     * Folder id for testing.
     */
    protected final int folderId = 2002;

    /**
     * Mock configuration handler property.
     */
    protected Configuration mockConfig = EasyMock.createMock(Configuration.class);

    /**
     * Mock data source for testing.
     */
    protected DataSource mockSource;

    /**
     * Setup for tests.
     *
     * @throws Exception If there are issues mocking
     */
    @Before
    public void setUp() throws Exception {
        mockSource = EasyMock.createMock(DataSource.class);
        importer = PowerMock.createPartialMock(TwitterContactsImport.class,
            new String[] { "getAuthorizationBuilder", "buildContactsUrl", "getContactsRequest",
                "getExistingContacts", "parseNewContacts" },
            mockSource);

        Whitebox.setInternalState(importer, "config", mockConfig);

        PowerMock.mockStatic(TwitterContactsUtil.class);
    }

    /**
     * Test method for {@link TwitterContactsImport#importData}<br>
     * Validates that the method fetches contacts and passes along to parse
     * utilites.
     *
     * @throws Exception If there are issues testing
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testImportData() throws Exception {
        final TwitterAuthorizationBuilder mockBuilder = EasyMock.createMock(TwitterAuthorizationBuilder.class);
        // expect to fetch mailbox and ds folder id
        expect(mockSource.getMailbox()).andReturn(null);
        expect(mockSource.getFolderId()).andReturn(folderId);
        // expect a fetch for existing contacts
        expect(importer.getExistingContacts(anyObject(), eq(folderId)))
            .andReturn(new HashSet<String>());
        // expect to create an authorization builder
        expect(importer.getAuthorizationBuilder()).andReturn(mockBuilder);
        // expect buildContactsUrl to be called
        expect(importer.buildContactsUrl(anyObject()))
            .andReturn(TwitterContactConstants.CONTACTS_URI.getValue());
        // expect to set a null cursor
        expect(mockBuilder.withParam("cursor", null)).andReturn(mockBuilder);
        // expect to execute the authorization builder
        expect(mockBuilder.build()).andReturn(authHeader);
        final String jsonData = "{\"next_cursor\":0,\"next_cursor_str\":\"0\",\"previous_cursor\":0,\"previous_cursor_str\":\"0\",\"users\":[{\"description\":\"Test User.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555576,\"name\":\"Some Test\",\"screen_name\":\"SomeTest\"},{\"description\":\"Mr Unit's tweet space.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555577,\"name\":\"Test Unit\",\"screen_name\":\"IntegrationTest\"},{\"description\":\"Test User2.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555578,\"name\":\"Some Test2\",\"screen_name\":\"SomeTest2\"}]}";
        final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
        expect(importer.getContactsRequest(anyObject(), matches(authHeader))).andReturn(jsonResponse);
        // expect parse new contacts to be called
        importer.parseNewContacts(anyObject(Set.class), anyObject(JsonNode.class),
            anyObject(List.class));
        PowerMock.expectLastCall();

        replay(mockConfig);
        replay(mockBuilder);
        replay(mockSource);
        replay(importer);

        importer.importData(null, true);

        verify(mockConfig);
        verify(mockBuilder);
        verify(mockSource);
        verify(importer);
    }

    /**
     * Test method for {@link TwitterContactsImport#parseNewContacts}<br>
     * Validates that the method adds contacts to the create list when they do
     * not already exist    .
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContacts() throws Exception {
        final TwitterContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(TwitterContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("519555570");
        final String jsonData = "{\"next_cursor\":0,\"next_cursor_str\":\"0\",\"previous_cursor\":0,\"previous_cursor_str\":\"0\",\"users\":[{\"description\":\"Test User.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555576,\"name\":\"Some Test\",\"screen_name\":\"SomeTest\"},{\"description\":\"Mr Unit's tweet space.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555577,\"name\":\"Test Unit\",\"screen_name\":\"IntegrationTest\"},{\"description\":\"Test User2.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555578,\"name\":\"Some Test2\",\"screen_name\":\"SomeTest2\"}]}";
        final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("users");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        // expect to parse 3 contacts
        TwitterContactsUtil.parseContact(anyObject(JsonNode.class), anyObject(DataSource.class));
        PowerMock.expectLastCall().andReturn(null).times(3);

        PowerMock.replay(TwitterContactsUtil.class);

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        PowerMock.verify(TwitterContactsUtil.class);

        // ensure we have 3 entries
        assertEquals(3, createList.size());
    }

    /**
     * Test method for {@link TwitterContactsImport#parseNewContacts}<br>
     * Validates that the method does not add contact to the create list when
     * they already exist.
     *
     * @throws Exception If there are issues testing
     */
    @Test
    public void testParseNewContactsWhenExists() throws Exception {
        final TwitterContactsImport localImporter = PowerMock
            .createPartialMockForAllMethodsExcept(TwitterContactsImport.class, "parseNewContacts");
        final Set<String> existingContacts = new HashSet<String>();
        existingContacts.add("519555576");
        existingContacts.add("519555577");
        existingContacts.add("519555578");
        final String jsonData = "{\"next_cursor\":0,\"next_cursor_str\":\"0\",\"previous_cursor\":0,\"previous_cursor_str\":\"0\",\"users\":[{\"description\":\"Test User.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555576,\"name\":\"Some Test\",\"screen_name\":\"SomeTest\"},{\"description\":\"Mr Unit's tweet space.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555577,\"name\":\"Test Unit\",\"screen_name\":\"IntegrationTest\"},{\"description\":\"Test User2.\",\"entities\":{\"description\":{\"urls\":[]},\"url\":{\"urls\":[{\"display_url\":\"example.com\",\"expanded_url\":\"http://www.example.com\"}]}},\"id\":519555578,\"name\":\"Some Test2\",\"screen_name\":\"SomeTest2\"}]}";
        final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
        final JsonNode jsonContacts = jsonResponse.get("users");
        final List<ParsedContact> createList = new ArrayList<ParsedContact>();

        localImporter.parseNewContacts(existingContacts, jsonContacts, createList);

        assertEquals(0, createList.size());
    }

}
