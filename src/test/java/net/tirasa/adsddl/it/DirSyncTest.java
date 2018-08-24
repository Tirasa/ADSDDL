/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.it;

import com.sun.jndi.ldap.ctl.DirSyncResponseControl;
import java.util.HashSet;
import java.util.Set;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import net.tirasa.adsddl.ntsd.controls.DirSyncControl;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;

import org.junit.Test;

public class DirSyncTest extends AbstractTest {

    private static final long serialVersionUID = 1L;

    @Test
    public void syncUser() throws Exception {
        // -----------------------------------
        // Create search control
        // -----------------------------------
        final SearchControls searchCtls = createDefaultSearchControls();
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchCtls.setReturningAttributes(null);
        searchCtls.setTimeLimit(20000);
        // -----------------------------------

        // retrieve latest sync token
        ctx.setRequestControls(new Control[] { new DirSyncControl().setFlags(0x00000801) });

        Pair<SyncToken, Set<SearchResult>> res = search(ctx, "(cn=__CONNID-NORES__)", searchCtls, true);

        //  New user
        final String id = "syncUser01";
        final Attributes attrs = new BasicAttributes(true);
        attrs.put(new BasicAttribute("cn", id));
        attrs.put(new BasicAttribute("sn", id));
        attrs.put(new BasicAttribute("givenName", id));
        attrs.put(new BasicAttribute("displayName", id));
        attrs.put(new BasicAttribute("sAMAccountName", id));
        attrs.put(new BasicAttribute("userPrincipalName", id + "@test.org"));
        attrs.put(new BasicAttribute("userPassword", "password"));
        attrs.put(new BasicAttribute("objectClass", "top"));
        attrs.put(new BasicAttribute("objectClass", "person"));
        attrs.put(new BasicAttribute("objectClass", "organizationalPerson"));
        attrs.put(new BasicAttribute("objectClass", "user"));

        try {
            ctx.createSubcontext("CN=" + id + ",CN=Users," + baseContext, attrs);
        } catch (NamingException ne1) {
            try {
                LOG.debug("Error creating user {}", id, ne1);
                ctx.destroySubcontext("CN=" + id + ",CN=Users," + baseContext);
                ctx.createSubcontext("CN=" + id + ",CN=Users," + baseContext, attrs);
            } catch (NamingException ne2) {
                ne2.printStackTrace();
                LOG.error("Error creating user {}", id, ne2);
                assert (false);
            }

        }

        try {
            // Check for user create synchronization
            ctx.setRequestControls(new Control[] { new DirSyncControl((byte[]) res.getLeft().getValue()) });
            Pair<SyncToken, Set<SearchResult>> previous = search(ctx, createDirSyncUFilter(), searchCtls, true);
            Assert.assertEquals(0, previous.getRight().size());

            // check for group update membership synchronization
            ModificationItem[] mod = new ModificationItem[] { new ModificationItem(
                DirContext.ADD_ATTRIBUTE, new BasicAttribute("member", "CN=" + id + ",CN=Users," + baseContext))
            };

            try {
                ctx.modifyAttributes(prop.getProperty("membership"), mod);
            } catch (NamingException e) {
                LOG.error("Error adding membership to Domain Guests", e);
                assert (false);
            }

            ctx.setRequestControls(new Control[] { new DirSyncControl((byte[]) res.getLeft().getValue()) });
            res = search(ctx, createDirSyncUFilter(), searchCtls, true);
            Assert.assertEquals(2, res.getRight().size());

            ctx.setRequestControls(new Control[] { new DirSyncControl((byte[]) previous.getLeft().getValue()) });
            res = search(ctx, createDirSyncUFilter(), searchCtls, true);
            Assert.assertEquals(1, res.getRight().size());
        } finally {
            ctx.destroySubcontext("CN=" + id + ",CN=Users," + baseContext);
        }
    }

    private static SearchControls createDefaultSearchControls() {
        SearchControls result = new SearchControls();
        result.setCountLimit(0);
        result.setDerefLinkFlag(true);
        result.setReturningObjFlag(false);
        result.setTimeLimit(0);
        return result;
    }

    private String createDirSyncUFilter() {
        final StringBuilder filter = new StringBuilder();
        final StringBuilder mfilter = new StringBuilder();
        final StringBuilder ufilter = new StringBuilder();

        mfilter.append("(objectClass=group)");

        ufilter.append("(&").
                append("(objectCategory=person)(objectClass=user)").
                append("(memberOf").append("=").append(prop.getProperty("membership")).append(")").
                append(")");

        filter.append("(|").
                append(ufilter).
                append(mfilter).
                append("(&(isDeleted=").append("TRUE").append(")(objectClass=user))").
                append(")");

        LOG.debug("Generated filter {}", filter.toString());
        return filter.toString();
    }

    private Pair<SyncToken, Set<SearchResult>> search(
            final LdapContext ctx,
            final String filter,
            final SearchControls searchCtls,
            final boolean updateLastSyncToken) {

        final Set<SearchResult> result = new HashSet<SearchResult>();
        SyncToken latestSyncToken = null;

        String baseContextDn = prop.getProperty("baseContext");

        if (LOG.isDebugEnabled()) {
            LOG.debug("Searching from {}", baseContextDn);
        }

        try {
            final NamingEnumeration<SearchResult> answer = ctx.search(baseContextDn, filter, searchCtls);

            while (answer.hasMoreElements()) {
                result.add(answer.nextElement());
            }

            if (updateLastSyncToken) {
                final Control[] rspCtls = ctx.getResponseControls();

                if (rspCtls != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Response Controls: {}", rspCtls.length);
                    }

                    for (Control rspCtl : rspCtls) {
                        if (rspCtl instanceof DirSyncResponseControl) {
                            DirSyncResponseControl dirSyncRspCtl = (DirSyncResponseControl) rspCtl;
                            latestSyncToken = new SyncToken(dirSyncRspCtl.getCookie());
                        }
                    }

                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Latest sync token set to {}", latestSyncToken);
                    }
                }
            }
        } catch (NamingException e) {
            LOG.error("While searching base context {} with filter {} and search controls {}",
                    baseContextDn, filter, searchCtls, e);
        }

        return Pair.of(latestSyncToken, result);
    }
}
