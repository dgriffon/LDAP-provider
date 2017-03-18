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

import com.google.common.collect.Lists;
import org.jahia.modules.external.users.Member;
import org.jahia.services.usermanager.ldap.LDAPUserGroupProvider;
import org.jahia.services.usermanager.ldap.cache.LDAPAbstractCacheEntry;
import org.jahia.services.usermanager.ldap.cache.LDAPGroupCacheEntry;
import org.jahia.services.usermanager.ldap.cache.LDAPUserCacheEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.NameClassPairCallbackHandler;
import org.springframework.ldap.support.LdapUtils;

import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.List;

/**
 * Calback handler for dynamic members, retrieve the list of members
 */
public class DynMembersNameClassPairCallbackHandler implements NameClassPairCallbackHandler {

    private LDAPUserGroupProvider ldapUserGroupProvider;
    private List<Member> members = Lists.newArrayList();
    private static Logger logger = LoggerFactory.getLogger(DynMembersNameClassPairCallbackHandler.class);
    private String key;


    public DynMembersNameClassPairCallbackHandler(LDAPUserGroupProvider ldapUserGroupProvider, String key) {
        this.ldapUserGroupProvider = ldapUserGroupProvider;
        this.key = key;
    }

    public List<Member> getMembers() {
        return members;
    }

    @Override
    public void handleNameClassPair(NameClassPair nameClassPair) throws NamingException {

        if (nameClassPair instanceof SearchResult) {

            SearchResult searchResult = (SearchResult) nameClassPair;

            // try to know if we deal with a group or a user
            Boolean isUser = ldapUserGroupProvider.guessUserOrGroupFromDN(searchResult.getNameInNamespace());

            // try to retrieve the object from the cache
            LDAPAbstractCacheEntry cacheEntry;
            if (isUser != null) {
                if (isUser) {
                    cacheEntry = ldapUserGroupProvider.getLdapCacheManager().getUserCacheEntryByDn(key, searchResult.getNameInNamespace());
                } else {
                    cacheEntry = ldapUserGroupProvider.getLdapCacheManager().getGroupCacheEntryByDn(key, searchResult.getNameInNamespace());
                }
            } else {
                // look in all cache
                cacheEntry = ldapUserGroupProvider.getLdapCacheManager().getUserCacheEntryByDn(key, searchResult.getNameInNamespace());
                if (cacheEntry == null) {
                    cacheEntry = ldapUserGroupProvider.getLdapCacheManager().getGroupCacheEntryByDn(key, searchResult.getNameInNamespace());
                    isUser = cacheEntry != null ? false : null;
                } else {
                    isUser = true;
                }
            }
            if (cacheEntry != null) {
                if (isUser) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Dynamic member {} retrieved from cache and resolved as a user", searchResult.getNameInNamespace());
                    }
                    members.add(new Member(cacheEntry.getName(), Member.MemberType.USER));
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Dynamic member {} retrieved from cache and resolved as a group", searchResult.getNameInNamespace());
                    }
                    members.add(new Member(cacheEntry.getName(), Member.MemberType.GROUP));
                }
            }

            // try the objectclass
            Boolean isDynamic = false;
            searchResult.getAttributes().get(LDAPUserGroupProvider.OBJECTCLASS_ATTRIBUTE).getAll();
            List<String> objectclasses = new ArrayList<String>();
            LdapUtils.collectAttributeValues(searchResult.getAttributes(), LDAPUserGroupProvider.OBJECTCLASS_ATTRIBUTE, objectclasses, String.class);
            if (objectclasses.contains(ldapUserGroupProvider.getUserConfig().getSearchObjectclass())) {
                isUser = true;
            } else if (objectclasses.contains(ldapUserGroupProvider.getUserConfig().getSearchObjectclass())) {
                isUser = false;
            } else if (ldapUserGroupProvider.getGroupConfig().isDynamicEnabled() && objectclasses.contains(ldapUserGroupProvider.getGroupConfig().getDynamicSearchObjectclass()
            )) {
                isUser = false;
                isDynamic = true;
            }
            if (isUser != null) {
                if (isUser) {
                    handleUserNameClassPair(nameClassPair, searchResult);
                } else {
                    handleGroupNameClassPair(nameClassPair, searchResult, isDynamic);
                }
                return;
            }

            // try to guess the type on attributes present in the searchresult
            List<String> searchResultsAttr = new ArrayList<String>();
            NamingEnumeration<String> attrs = searchResult.getAttributes().getIDs();
            while (attrs.hasMore()) {
                searchResultsAttr.add(attrs.next());
            }
            List<String> commonUserAttrs = ldapUserGroupProvider.getCommonAttributes(searchResultsAttr, ldapUserGroupProvider.getUserAttributes());
            List<String> commonGroupAttrs = ldapUserGroupProvider.getCommonAttributes(searchResultsAttr, ldapUserGroupProvider.getGroupAttributes(isDynamic));
            if (commonUserAttrs.contains(ldapUserGroupProvider.getUserConfig().getUidSearchAttribute()) && commonUserAttrs.size() > commonGroupAttrs.size()) {
                handleUserNameClassPair(nameClassPair, searchResult);
                return;
            } else if (commonGroupAttrs.contains(ldapUserGroupProvider.getGroupConfig().getSearchAttribute())) {
                handleGroupNameClassPair(nameClassPair, searchResult, false);
                return;
            }

            // type not resolved
            logger.warn("Dynamic member: " + searchResult.getNameInNamespace() + " not resolved as a user or a group");
        } else {
            logger.error("Unexpected NameClassPair " + nameClassPair + " in " + getClass().getName());
        }
    }

    private void handleGroupNameClassPair(NameClassPair nameClassPair, SearchResult searchResult, Boolean isDynamic) throws NamingException {
        GroupNameClassPairCallbackHandler groupNameClassPairCallbackHandler = new GroupNameClassPairCallbackHandler(ldapUserGroupProvider, null, isDynamic);
        groupNameClassPairCallbackHandler.handleNameClassPair(nameClassPair);
        LDAPGroupCacheEntry groupCacheEntry = groupNameClassPairCallbackHandler.getCacheEntry();
        ldapUserGroupProvider.getLdapCacheManager().cacheGroup(key, groupCacheEntry);
        members.add(new Member(groupCacheEntry.getName(), Member.MemberType.GROUP));
        if (logger.isDebugEnabled()) {
            logger.debug("Dynamic member {} resolved as a {}", searchResult.getNameInNamespace(), isDynamic ? " dynamic group" : " group");
        }
    }

    private void handleUserNameClassPair(NameClassPair nameClassPair, SearchResult searchResult) throws NamingException {
        UserNameClassPairCallbackHandler userNameClassPairCallbackHandler = new UserNameClassPairCallbackHandler( ldapUserGroupProvider, null, key);
        userNameClassPairCallbackHandler.handleNameClassPair(nameClassPair);
        LDAPUserCacheEntry userCacheEntry = userNameClassPairCallbackHandler.getCacheEntry();
        if (userCacheEntry != null) {
            ldapUserGroupProvider.getLdapCacheManager().cacheUser(key, userCacheEntry);
            members.add(new Member(userCacheEntry.getName(), Member.MemberType.USER));
            logger.debug("Dynamic member {} resolved as a user", searchResult.getNameInNamespace());
        }
    }
}
