/*
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
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

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
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.DataSource;
import com.zimbra.cs.mime.ParsedContact;
import com.zimbra.oauth.handlers.impl.FacebookContactsImport.FacebookContactsUtil;
import com.zimbra.oauth.handlers.impl.FacebookOAuth2Handler.FacebookConstants;
import com.zimbra.oauth.utilities.Configuration;

/**
 * Test class for {@link FacebookContactsImport}.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DataSource.class, FacebookContactsImport.class, FacebookContactsUtil.class })
public class FacebookContactsImportTest {

  /**
   * Class under test.
   */
  protected FacebookContactsImport importer;

  /**
   * Access token for testing.
   */
  protected final String accessToken = "test-access-token";

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
    importer = PowerMock.createPartialMock(FacebookContactsImport.class,
      new String[] {"refresh", "getExistingContacts", "buildContactsUrl",
        "getContactsRequest", "parseNewContacts"},
      mockSource);

    Whitebox.setInternalState(importer, "config", mockConfig);

    PowerMock.mockStatic(FacebookContactsUtil.class);
  }

  /**
   * Test method for {@link FacebookContactsImport#importData}<br>
   * Validates that the method fetches contacts and passes along to parse
   * utilites.
   *
   * @throws Exception If there are issues testing
   */
  @SuppressWarnings("unchecked")
  @Test
  public void testImportData() throws Exception {
    expect(mockSource.getMailbox()).andReturn(null);
    expect(mockSource.getFolderId()).andReturn(folderId);
    // expect a fetch for existing contacts
    expect(importer.getExistingContacts(anyObject(), eq(folderId), anyObject()))
        .andReturn(new HashSet<String>());
    // expect a fetch for refresh token
    expect(importer.refresh()).andReturn(accessToken);
    // expect buildContactsUrl to be called
    expect(importer.buildContactsUrl(anyObject(), anyObject()))
        .andReturn(FacebookConstants.CONTACTS_URI_TEMPLATE.getValue());
    final String jsonData = "{\"data\": [{\"id\": \"114606492762739\",\"name\": \"Ullrich Albfdjafgjfjh Valtchanovstein\"},{\"id\": \"113255442901577\",\"name\": \"Elizabeth Albfeacfecjgh Riceberg\"},{\"id\": \"107932500100943\",\"name\": \"Maria Albfebehjbbed Schrockman\"},{\"id\": \"108947766668167\",\"name\": \"Dave Albfehhcahafb Bushakstein\"}],\"paging\": {\"cursors\": {\"after\": \"dVI1WlhKVFJkQVdB\",\"before\": \"YnFkVXkteXIyQldR\"}},\"summary\": {\"total_count\": 4}}";
    final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
    expect(importer.getContactsRequest(anyObject())).andReturn(jsonResponse);
    // expect parse new contacts to be called
    importer.parseNewContacts(anyObject(Set.class), anyObject(JsonNode.class),
        anyObject(String.class), anyObject(List.class));
    PowerMock.expectLastCall();

    replay(mockConfig);
    replay(mockSource);
    replay(importer);

    importer.importData(null, true);

    verify(mockConfig);
    verify(mockSource);
    verify(importer);
  }

  /**
   * Test method for {@link FacebookContactsImport#parseNewContacts}<br>
   * Validates that the method adds a contact to the create list when it does
   * not already exist.
   *
   * @throws Exception If there are issues testing
   */
  @Test
  public void testParseNewContacts() throws Exception {
    final FacebookContactsImport localImporter = PowerMock
        .createPartialMockForAllMethodsExcept(FacebookContactsImport.class, "parseNewContacts");
    final Set<String> existingContacts = new HashSet<String>();
    existingContacts.add("111111111111");
    final String jsonData = "{\"data\": [{\"id\": \"108947766668167\",\"name\": \"Dave Albfehhcahafb Bushakstein\"}],\"paging\": {\"cursors\": {\"after\": \"lhKVFJkQVdB\",\"before\": \"kNtYnFkVXkteXIyQldR\"}},\"summary\": {\"total_count\": 1}}";
    final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
    final JsonNode jsonContacts = jsonResponse.get("data");
    final String matcherName = "id";
    final List<ParsedContact> createList = new ArrayList<ParsedContact>();

    localImporter.parseNewContacts(existingContacts, jsonContacts, matcherName, createList);

    assertEquals(1, createList.size());
  }

  /**
   * Test method for {@link FacebookContactsImport#parseNewContacts}<br>
   * Validates that the method does not add a contact to the create list when
   * it already exists.
   *
   * @throws Exception If there are issues testing
   */
  @Test
  public void testParseNewContactsWhenExists() throws Exception {
    final FacebookContactsImport localImporter = PowerMock
        .createPartialMockForAllMethodsExcept(FacebookContactsImport.class, "parseNewContacts");
    final Set<String> existingContacts = new HashSet<String>();
    existingContacts.add("108947766668167");
    final String jsonData = "{\"data\": [{\"id\": \"108947766668167\",\"name\": \"Dave Albfehhcahafb Bushakstein\"}],\"paging\": {\"cursors\": {\"after\": \"lhKVFJkQVdB\",\"before\": \"kNtYnFkVXkteXIyQldR\"}},\"summary\": {\"total_count\": 1}}";
    final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
    final JsonNode jsonContacts = jsonResponse.get("data");
    final String matcherName = "id";
    final List<ParsedContact> createList = new ArrayList<ParsedContact>();

    localImporter.parseNewContacts(existingContacts, jsonContacts, matcherName, createList);

    assertEquals(0, createList.size());
  }

  /**
   * Test method for {@link FacebookContactsImport#importData}<br>
   * Validates that the method throws a ServiceException when the Facebook
   * friends api returns an error response.
   *
   * @throws Exception If there are issues testing
   */
  @Test
  public void testImportDataErrorApiResponse() throws Exception {
    expect(mockSource.getMailbox()).andReturn(null);
    expect(mockSource.getFolderId()).andReturn(folderId);
    // expect a fetch for existing contacts
    expect(importer.getExistingContacts(anyObject(), eq(folderId), anyObject()))
        .andReturn(new HashSet<String>());
    // expect a fetch for refresh token
    expect(importer.refresh()).andReturn(accessToken);
    // expect buildContactsUrl to be called
    expect(importer.buildContactsUrl(anyObject(), anyObject()))
        .andReturn(FacebookConstants.CONTACTS_URI_TEMPLATE.getValue());
    final String jsonData = "{\"error\": {\"message\": \"Error validating access token: Session has expired on Monday, 11-Jun-18 11:00:00 PDT. The current time is Thursday, 14-Jun-18 22:26:28 PDT.\",\"type\": \"OAuthException\",\"code\": 190,\"error_subcode\": 463,\"fbtrace_id\": \"Ey9c3rSW3cD\"}}";
    final JsonNode jsonResponse = OAuth2Handler.mapper.readTree(jsonData);
    expect(importer.getContactsRequest(anyObject())).andReturn(jsonResponse);
    PowerMock.expectLastCall();

    replay(mockConfig);
    replay(mockSource);
    replay(importer);
    try {
      importer.importData(null, true);
    } catch (final ServiceException e) {
      assertEquals(ServiceException.FAILURE, e.getCode());
      return;
    }
    fail("Expected exception to be thrown for api error response.");
  }
}
