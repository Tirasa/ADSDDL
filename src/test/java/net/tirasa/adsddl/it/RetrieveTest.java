/**
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;

import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.utils.Hex;

import org.junit.Test;

public class RetrieveTest extends AbstractTest {

    private static final long serialVersionUID = 1L;

    @Test
    public void searchBySID() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "sAMAccountName", "objectSID" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        assertTrue(results.hasMore());

        SearchResult res = results.next();
        final byte[] src = (byte[]) res.getAttributes().get("objectSID").get();
        final String sAMAccountName = String.class.cast(res.getAttributes().get("sAMAccountName").get());

        final SID sid = SID.parse(src);

        // query by escaped bynary SID
        results = ctx.search(baseContext, "objectSID=" + Hex.getEscaped(sid.toByteArray()), controls);
        assertTrue(results.hasMore());

        res = results.next();
        assertEquals(sAMAccountName, String.class.cast(res.getAttributes().get("sAMAccountName").get()));

        // query by SID string
        results = ctx.search(baseContext, "objectSID=" + sid.toString(), controls);
        assertTrue(results.hasMore());

        res = results.next();
        assertEquals(sAMAccountName, String.class.cast(res.getAttributes().get("sAMAccountName").get()));
    }

    @Test
    public void unMarshall() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        assertTrue(results.hasMore());

        final SearchResult res = results.next();
        final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        UnMarshall(src);
    }

    @Test
    public void userChangePassword() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
            UserChangePassword(src);
        }
    }

    @Test
    public void ucpChangeUnMarshall() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
            ucpChangeUnMarshall(src);
        }
    }
}
