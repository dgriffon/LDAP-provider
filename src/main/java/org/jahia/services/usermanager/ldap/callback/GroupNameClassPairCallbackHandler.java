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

import org.jahia.services.usermanager.JahiaGroup;
import org.jahia.services.usermanager.JahiaGroupImpl;
import org.jahia.services.usermanager.ldap.LDAPUserGroupProvider;
import org.jahia.services.usermanager.ldap.cache.LDAPGroupCacheEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.NameClassPairCallbackHandler;

import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Callback handler for a single group, create the corresponding cache entry
 */
public class GroupNameClassPairCallbackHandler extends AbstractNameClassPairCallbackHandler implements NameClassPairCallbackHandler {

    private static Logger logger = LoggerFactory.getLogger(GroupNameClassPairCallbackHandler.class);

    private LDAPUserGroupProvider ldapUserGroupProvider;
    private LDAPGroupCacheEntry cacheEntry;
    private boolean isDynamic;

    public LDAPGroupCacheEntry getCacheEntry() {
        return cacheEntry;
    }

    public GroupNameClassPairCallbackHandler(LDAPUserGroupProvider ldapUserGroupProvider, LDAPGroupCacheEntry cacheEntry, boolean isDynamic) {
        super(ldapUserGroupProvider.getUserConfig(), ldapUserGroupProvider.getGroupConfig());
        this.ldapUserGroupProvider = ldapUserGroupProvider;
        this.cacheEntry = cacheEntry;
        this.isDynamic = isDynamic;
    }

    @Override
    public void handleNameClassPair(NameClassPair nameClassPair) throws NamingException {
        if (nameClassPair instanceof SearchResult) {
            SearchResult searchResult = (SearchResult) nameClassPair;
            cacheEntry = attributesToGroupCacheEntry(searchResult.getAttributes(), cacheEntry);
            cacheEntry.setDynamic(isDynamic);
            if (isDynamic && searchResult.getAttributes().get(ldapUserGroupProvider.getGroupConfig().getDynamicMembersAttribute()) != null) {
                cacheEntry.setDynamicMembersURL(searchResult.getAttributes().get(ldapUserGroupProvider.getGroupConfig().getDynamicMembersAttribute()).get().toString());
            }
            cacheEntry.setDn(searchResult.getNameInNamespace());
        } else {
            logger.error("Unexpected NameClassPair " + nameClassPair + " in " + getClass().getName());
        }
    }

    /**
     * Populate the given cache entry or create new one if the given is null with the LDAP attributes
     *
     * @param attrs
     * @param groupCacheEntry
     * @return
     * @throws NamingException
     */
    private LDAPGroupCacheEntry attributesToGroupCacheEntry(Attributes attrs, LDAPGroupCacheEntry groupCacheEntry) throws NamingException {
        String groupId = (String) attrs.get(groupConfig.getSearchAttribute()).get();
        JahiaGroup jahiaGroup = new JahiaGroupImpl(LDAPUserGroupProvider.encode(groupId), null, null, attributesToJahiaProperties(attrs, false));

        if (groupCacheEntry == null) {
            groupCacheEntry = new LDAPGroupCacheEntry(jahiaGroup.getName());
        }
        groupCacheEntry.setExist(true);
        groupCacheEntry.setGroup(jahiaGroup);
        return groupCacheEntry;
    }
}
