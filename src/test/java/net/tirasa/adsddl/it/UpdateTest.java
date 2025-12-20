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
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;
import org.junit.Assert;
import org.junit.Test;

public class UpdateTest extends AbstractTest {

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
    public void userCanChangePassword() throws Exception {
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

        results.close();

        final Attribute ntSecurityDescriptor = new BasicAttribute(
                "ntSecurityDescriptor", userCannotChangePassword(sddl, false).toByteArray());

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
            if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(SDDLHelper.UCP_OBJECT_GUID)) {

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

        assertEquals(2, found.size());
    }

    @Test
    public void userCannotChangePassword() throws Exception {
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

        results.close();

        final Attribute ntSecurityDescriptor = new BasicAttribute(
                "ntSecurityDescriptor", userCannotChangePassword(sddl, true).toByteArray());

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
            if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(SDDLHelper.UCP_OBJECT_GUID)) {

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

        assertEquals(2, found.size());
    }

    private SDDL userCannotChangePassword(final SDDL sddl, final boolean cannot) {
        final AceType type = cannot ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

        ACE self = null;
        ACE all = null;

        final List<ACE> aces = sddl.getDacl().getAces();
        for (int i = 0; (all == null || self == null) && i < aces.size(); i++) {
            final ACE ace = aces.get(i);

            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(SDDLHelper.UCP_OBJECT_GUID)) {

                    final SID sid = ace.getSid();
                    if (sid.getSubAuthorities().size() == 1) {
                        if (self == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x00 })) {
                            self = ace;
                            self.setType(type);
                        } else if (all == null && Arrays.equals(
                                sid.getIdentifierAuthority(), new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && Arrays.equals(
                                        sid.getSubAuthorities().get(0), new byte[] { 0x00, 0x00, 0x00, 0x0a })) {
                            all = ace;
                            all.setType(type);
                        }
                    }
                }
            }
        }

        if (self == null) {
            // prepare aces
            self = ACE.newInstance(type);
            self.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            self.setObjectType(GUID.getGuidAsByteArray(SDDLHelper.UCP_OBJECT_GUID));
            self.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000001, 6));
            sid.addSubAuthority(NumberFacility.getBytes(0));
            self.setSid(sid);
            sddl.getDacl().getAces().add(self);
        }

        if (all == null) {
            all = ACE.newInstance(type);
            all.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
            all.setObjectType(GUID.getGuidAsByteArray(SDDLHelper.UCP_OBJECT_GUID));
            all.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
            final SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000005, 6));
            sid.addSubAuthority(NumberFacility.getBytes(0x0A));
            all.setSid(sid);
            sddl.getDacl().getAces().add(all);
        }

        return sddl;
    }
}
