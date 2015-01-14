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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.SDFlagsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class UpdateTest extends AbstractTest {

    private static final long serialVersionUID = 1L;

    @Test
    public void readAllAndSaveWithoutChanges() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        SearchResult res = results.next();
        final String dn = res.getNameInNamespace();

        final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

        final SDDL sddl = new SDDL(orig);

        results.close();

        final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor", sddl.toByteArray());

        final ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

        ctx.modifyAttributes(dn, mods);

        results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        res = results.next();
        assertEquals(dn, res.getNameInNamespace());

        final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        assertTrue(Arrays.equals(orig, changed));

        // check for unmashall
        assertNotNull(new SDDL(changed));
    }

    @Test
    public void readDACLAndSaveWithoutChanges() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        SearchResult res = results.next();
        final String dn = res.getNameInNamespace();

        final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

        SDDL sddl = new SDDL(orig);
        assertNull(sddl.getOwner());
        assertNull(sddl.getGroup());
        assertNull(sddl.getSacl());
        assertNotNull(sddl.getDacl());

        results.close();

        final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor", sddl.toByteArray());

        final ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

        ctx.modifyAttributes(dn, mods);

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });
        results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        res = results.next();
        assertEquals(dn, res.getNameInNamespace());

        final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        assertFalse(Arrays.equals(orig, changed));

        sddl = new SDDL(changed);
        assertNotNull(sddl.getDacl());
        assertNotNull(sddl.getSacl());
        assertNotNull(sddl.getOwner());
        assertNotNull(sddl.getGroup());
    }

    @Test
    public void readAllAndSaveWithChanges() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        SearchResult res = results.next();
        final String dn = res.getNameInNamespace();

        final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

        SDDL sddl = new SDDL(orig);
        assertNotNull(sddl.getOwner());
        assertNotNull(sddl.getGroup());
        assertNotNull(sddl.getSacl());
        assertNotNull(sddl.getDacl());

        results.close();

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

        final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor", sddl.toByteArray());

        final ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

        ctx.modifyAttributes(dn, mods);

        results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        res = results.next();
        assertEquals(dn, res.getNameInNamespace());

        final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        assertFalse(Arrays.equals(orig, changed));

        sddl = new SDDL(changed);
        assertNotNull(sddl.getDacl());
        assertNotNull(sddl.getSacl());
        assertNotNull(sddl.getOwner());
        assertNotNull(sddl.getGroup());
    }

    @Test
    public void readDaclAndReplaceAces() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        SearchResult res = results.next();
        final String dn = res.getNameInNamespace();

        final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

        SDDL sddl = new SDDL(orig);
        assertNull(sddl.getOwner());
        assertNull(sddl.getGroup());
        assertNull(sddl.getSacl());
        assertNotNull(sddl.getDacl());

        results.close();

        final List<ACE> toBeRemoved = new ArrayList<>();

        for (ACE ace : sddl.getDacl().getAces()) {
            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    printSID(ace.getSid());
                    toBeRemoved.add(ace);
                }
            }
        }

        assertFalse(toBeRemoved.isEmpty());

        final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor", sddl.toByteArray());

        final ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

        ctx.modifyAttributes(dn, mods);

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });
        results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        res = results.next();
        assertEquals(dn, res.getNameInNamespace());

        final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        assertFalse(Arrays.equals(orig, changed));

        sddl = new SDDL(changed);
        assertNotNull(sddl.getDacl());
        assertNotNull(sddl.getSacl());
        assertNotNull(sddl.getOwner());
        assertNotNull(sddl.getGroup());
    }

    @Test
    @Ignore
    public void readDaclAndRemoveAces() throws Exception {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        SearchResult res = results.next();
        final String dn = res.getNameInNamespace();

        final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

        SDDL sddl = new SDDL(orig);
        assertNull(sddl.getOwner());
        assertNull(sddl.getGroup());
        assertNull(sddl.getSacl());
        assertNotNull(sddl.getDacl());

        results.close();

        final List<ACE> toBeRemoved = new ArrayList<>();

        for (ACE ace : sddl.getDacl().getAces()) {
            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1
                            && ((Arrays.equals(
                                    sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                            && Arrays.equals(
                                    sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                            || (Arrays.equals(
                                    sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                            && Arrays.equals(
                                    sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a })))) {
                        toBeRemoved.add(ace);

                        if (log.isDebugEnabled()) {
                            printACE(ace);
                        }
                    }
                }
            }
        }

        assertFalse(toBeRemoved.isEmpty());

        sddl.getDacl().getAces().removeAll(toBeRemoved);

        final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor", sddl.toByteArray());

        final ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

        ctx.modifyAttributes(dn, mods);

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });
        results = ctx.search(baseContext, searchFilter, controls);

        if (!results.hasMore()) {
            Assert.fail();
        }

        res = results.next();
        assertEquals(dn, res.getNameInNamespace());

        final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
        assertFalse(Arrays.equals(orig, changed));

        sddl = new SDDL(changed);
        assertNotNull(sddl.getDacl());
        assertNotNull(sddl.getSacl());
        assertNotNull(sddl.getOwner());
        assertNotNull(sddl.getGroup());

        final List<ACE> found = new ArrayList<>();

        for (ACE ace : sddl.getDacl().getAces()) {
            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1
                            && ((Arrays.equals(
                                    sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                            && Arrays.equals(
                                    sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                            || (Arrays.equals(
                                    sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                            && Arrays.equals(
                                    sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a })))) {
                        found.add(ace);
                    }
                }
            }
        }

        assertTrue(found.isEmpty());
    }
}
