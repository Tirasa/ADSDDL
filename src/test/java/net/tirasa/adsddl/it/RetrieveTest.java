/* 
 * Copyright 2015 Tirasa.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.it;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.SDFlagsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import org.junit.Assert;
import org.junit.Test;

public class RetrieveTest extends AbstractTest {

    private static final long serialVersionUID = 1L;

    private static final String UCP_OBJECT_GUID = "AB721A53-1E2F-11D0-9819-00AA0040529B";

    @Test
    public void UnMarshall() throws Exception {

        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

            final SDDL sddl = new SDDL(src);

            if (log.isDebugEnabled()) {
                printSDDL(sddl);
            }

            final byte[] marshalled = sddl.toByteArray();

            Assert.assertTrue(Arrays.equals(src, marshalled));
        }
    }

    @Test
    public void UserChangePasswordTest() throws Exception {

        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
            final SDDL sddl = new SDDL(src);

            if (log.isDebugEnabled()) {
                printSDDL(sddl);
            }

            final byte[] marshalled = sddl.toByteArray();

            Assert.assertTrue(Arrays.equals(src, marshalled));

            assertFalse(sddl.getDacl().getAces().isEmpty());
            boolean found = false;
            for (ACE ace : sddl.getDacl().getAces()) {
                if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                        && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                    if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {
                        found = true;
                    }
                }
            }
            assertTrue(found);
        }
    }

    @Test
    public void ucpChangeUnMarshallTest() throws Exception {

        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        final NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final byte[] src = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
            final SDDL sddl = new SDDL(src);

            if (log.isDebugEnabled()) {
                printSDDL(sddl);
            }

            Assert.assertTrue(Arrays.equals(src, sddl.toByteArray()));

            for (ACE ace : sddl.getDacl().getAces()) {
                if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                        && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                    if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {
                        if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
                            ace.setType(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                        } else {
                            ace.setType(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE);
                        }
                    }
                }
            }

            Assert.assertFalse(Arrays.equals(src, sddl.toByteArray()));
        }
    }
}
