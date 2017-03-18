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

import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserImpl;
import org.jahia.services.usermanager.ldap.LDAPUserGroupProvider;
import org.jahia.services.usermanager.ldap.cache.LDAPUserCacheEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.NameClassPairCallbackHandler;

import javax.naming.NameClassPair;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/**
 * Callback handler for a single user, create the corresponding cache entry
 */
public class UserNameClassPairCallbackHandler extends AbstractNameClassPairCallbackHandler  implements NameClassPairCallbackHandler {

    private static Logger logger = LoggerFactory.getLogger(UserNameClassPairCallbackHandler.class);

    private LDAPUserCacheEntry cacheEntry;
    private String key;


    public LDAPUserCacheEntry getCacheEntry() {
        return cacheEntry;
    }
    public UserNameClassPairCallbackHandler(LDAPUserGroupProvider ldapUserGroupProvider, LDAPUserCacheEntry cacheEntry, String key) {
        super(ldapUserGroupProvider.getUserConfig(), ldapUserGroupProvider.getGroupConfig());
        this.cacheEntry = cacheEntry;
        this.key = key;
    }

    @Override
    public void handleNameClassPair(NameClassPair nameClassPair) throws NamingException {
        if (nameClassPair instanceof SearchResult) {
            SearchResult searchResult = (SearchResult) nameClassPair;
            cacheEntry = attributesToUserCacheEntry(searchResult.getAttributes(), cacheEntry);
            if (cacheEntry != null) {
                cacheEntry.setDn(searchResult.getNameInNamespace());
            }
        } else {
            logger.error("Unexpected NameClassPair " + nameClassPair + " in " + getClass().getName());
        }
    }

    /**
     * Populate the given cache entry or create new one if the given is null with the LDAP attributes
     *
     * @param attrs
     * @param userCacheEntry
     * @return
     * @throws NamingException
     */
    private LDAPUserCacheEntry attributesToUserCacheEntry(Attributes attrs, LDAPUserCacheEntry userCacheEntry) throws NamingException {
        Attribute uidAttr = attrs.get(userConfig.getUidSearchAttribute());
        if (uidAttr == null) {
            logger.warn("LDAP user entry is missing the required {} attribute. Skipping user. Available attributes: {}",
                    userConfig.getUidSearchAttribute(), attrs);
            return null;
        }
        String userId = (String) uidAttr.get();
        JahiaUser jahiaUser = new JahiaUserImpl(LDAPUserGroupProvider.encode(userId), null, attributesToJahiaProperties(attrs, true), key, null);
        if (userCacheEntry == null) {
            userCacheEntry = new LDAPUserCacheEntry(userId);
        }
        userCacheEntry.setExist(true);
        userCacheEntry.setUser(jahiaUser);
        return userCacheEntry;
    }
}
