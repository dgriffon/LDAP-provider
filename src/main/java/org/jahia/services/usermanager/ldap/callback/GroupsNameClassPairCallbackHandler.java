/**
 * ==========================================================================================
 * =                   JAHIA'S DUAL LICENSING - IMPORTANT INFORMATION                       =
 * ==========================================================================================
 *
 *                                 http://www.jahia.com
 *
 *     Copyright (C) 2002-2016 Jahia Solutions Group SA. All rights reserved.
 *
 *     THIS FILE IS AVAILABLE UNDER TWO DIFFERENT LICENSES:
 *     1/GPL OR 2/JSEL
 *
 *     1/ GPL
 *     ==================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE GPL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *     2/ JSEL - Commercial and Supported Versions of the program
 *     ===================================================================================
 *
 *     IF YOU DECIDE TO CHOOSE THE JSEL LICENSE, YOU MUST COMPLY WITH THE FOLLOWING TERMS:
 *
 *     Alternatively, commercial and supported versions of the program - also known as
 *     Enterprise Distributions - must be used in accordance with the terms and conditions
 *     contained in a separate written agreement between you and Jahia Solutions Group SA.
 *
 *     If you are unsure which license is appropriate for your use,
 *     please contact the sales department at sales@jahia.com.
 */
package org.jahia.services.usermanager.ldap.callback;

import org.jahia.services.usermanager.ldap.LDAPUserGroupProvider;
import org.jahia.services.usermanager.ldap.cache.LDAPGroupCacheEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.NameClassPairCallbackHandler;

import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import java.util.LinkedList;
import java.util.List;

/**
 * Callback handler for groups, retrieve the list of groupnames
 */
public class GroupsNameClassPairCallbackHandler implements NameClassPairCallbackHandler {

    private static Logger logger = LoggerFactory.getLogger(GroupsNameClassPairCallbackHandler.class);

    private LDAPUserGroupProvider ldapUserGroupProvider;
    private List<String> names = new LinkedList<>();
    private boolean isDynamic;
    private String key;

    public List<String> getNames() {
        return names;
    }

    public GroupsNameClassPairCallbackHandler(LDAPUserGroupProvider ldapUserGroupProvider, boolean isDynamic, String key) {

        this.ldapUserGroupProvider = ldapUserGroupProvider;
        this.isDynamic = isDynamic;
        this.key = key;
    }

    @Override
    public void handleNameClassPair(NameClassPair nameClassPair) throws NamingException {
        if (nameClassPair instanceof SearchResult) {
            SearchResult searchResult = (SearchResult) nameClassPair;
            LDAPGroupCacheEntry cacheEntry = ldapUserGroupProvider.getLdapCacheManager().getGroupCacheEntryByDn(key, searchResult.getNameInNamespace
                    ());
            if (cacheEntry == null || cacheEntry.getExist() == null || !cacheEntry.getExist().booleanValue()) {
                GroupNameClassPairCallbackHandler nameClassPairCallbackHandler = new GroupNameClassPairCallbackHandler(ldapUserGroupProvider, cacheEntry, isDynamic);
                nameClassPairCallbackHandler.handleNameClassPair(nameClassPair);
                cacheEntry = nameClassPairCallbackHandler.getCacheEntry();
                if (cacheEntry != null) {
                    ldapUserGroupProvider.getLdapCacheManager().cacheGroup(key, cacheEntry);
                }
            }
            if (cacheEntry != null) {
                names.add(cacheEntry.getName());
            }
        } else {
            logger.error("Unexpected NameClassPair " + nameClassPair + " in " + getClass().getName());
        }
    }
}
