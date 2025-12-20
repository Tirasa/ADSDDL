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
package net.tirasa.adsddl.unit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;
import org.junit.jupiter.api.BeforeAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractTest {

    protected static final Logger LOG = LoggerFactory.getLogger(AbstractTest.class);

    protected static final String SDDL_ALL_SAMPLE = "/sddlSample.bin";

    protected static final String DACL_ONLY_SAMPLE = "/daclOnlySample.bin";

    protected static String[] control = {
        "SR", "RM", "PS", "PD", "SI", "DI", "SC", "DC", "DT", "SS", "SD", "SP", "DD", "DP", "GD", "OD" };

    @BeforeAll
    public static void setUpConnection() throws IOException {
        // nothing to set up
    }

    protected void UnMarshall(final byte[] src) throws Exception {
        final SDDL sddl = new SDDL(src);

        if (LOG.isDebugEnabled()) {
            printSDDL(sddl);
            LOG.info(sddl.toString());
        }

        assertTrue(sddl.equals(new SDDL(sddl.toByteArray())));
    }

    protected void UserChangePassword(final byte[] src) throws Exception {
        final SDDL sddl = new SDDL(src);

        if (LOG.isDebugEnabled()) {
            printSDDL(sddl);
            LOG.info(sddl.toString());
        }

        // Assert.assertArrayEquals(src, sddl.toByteArray());
        assertFalse(sddl.getDacl().getAces().isEmpty());
        boolean found = false;
        for (ACE ace : sddl.getDacl().getAces()) {
            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(SDDLHelper.UCP_OBJECT_GUID)) {
                    found = true;
                }
            }
        }
        assertTrue(found);
    }

    protected void ucpChangeUnMarshall(final byte[] src) throws Exception {
        final SDDL sddl = new SDDL(src);

        if (LOG.isDebugEnabled()) {
            printSDDL(sddl);
            LOG.info(sddl.toString());
        }

        byte[] currentContiguousBlock = sddl.toByteArray();
        // Assert.assertArrayEquals(src, sddl.toByteArray());

        for (ACE ace : sddl.getDacl().getAces()) {
            if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                if (GUID.getGuidAsString(ace.getObjectType()).equals(SDDLHelper.UCP_OBJECT_GUID)) {
                    if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
                        ace.setType(AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE);
                    } else {
                        ace.setType(AceType.ACCESS_DENIED_OBJECT_ACE_TYPE);
                    }
                }
            }
        }

        assertFalse(Arrays.equals(currentContiguousBlock, sddl.toByteArray()));
    }

    protected void printSDDL(final SDDL sddl) {
        LOG.debug("Revision: {}", Hex.get(sddl.getRevision()));

        LOG.debug("Control flags: ");
        final boolean[] controlFlag = NumberFacility.getBits(sddl.getControlFlags());

        int count = 0;
        for (boolean flag : controlFlag) {
            if (flag) {
                LOG.debug(" - {}", control[count]);
            }
            count++;
        }

        // retrieve owner sid
        final SID owner = sddl.getOwner();
        if (owner != null) {
            LOG.debug("Owner SID: ....");
            printSID(owner);
        }

        // retrieve owner sid
        final SID group = sddl.getGroup();
        if (group != null) {
            LOG.debug("Group SID: ....");
            printSID(group);
        }

        final ACL sacl = sddl.getSacl();
        if (sacl != null) {
            LOG.debug("------------------------------------------");
            LOG.debug("SACL ");
            LOG.debug("------------------------------------------");

            printACL(sacl);
        }

        final ACL dacl = sddl.getDacl();
        if (dacl != null) {
            LOG.debug("------------------------------------------");
            LOG.debug("DACL ");
            LOG.debug("------------------------------------------");

            printACL(dacl);
        }
    }

    protected void printACL(final ACL acl) {
        LOG.debug("Acl Revision: {}", acl.getRevision().name());
        LOG.debug("Acl Size (bytes): {}", acl.getSize());

        int aceCount = acl.getAceCount();
        LOG.debug("Ace Count: {}", aceCount);

        for (int i = 0; i < aceCount; i++) {
            LOG.debug("------------------------------------------");
            LOG.debug("ACE " + i);
            LOG.debug("------------------------------------------");
            final ACE ace = acl.getAce(i);
            printACE(ace);
        }
    }

    protected void printSID(final SID sid) {
        LOG.debug("SID Revision: {}", Hex.get(sid.getRevision()));

        int subAuthCount = sid.getSubAuthorityCount();
        LOG.debug("SID Sub Authorities Count: {}", subAuthCount);
        LOG.debug("SID Identifier Authority: {}", Hex.get(sid.getIdentifierAuthority()));
        LOG.debug("SID Sub Authorities: ");
        for (byte[] sub : sid.getSubAuthorities()) {
            LOG.debug(" - {}", Hex.get(sub));
        }
    }

    protected void printACE(final ACE ace) {
        LOG.debug("AceType: {}", ace.getType().name());
        LOG.debug("AceFlags: ");
        for (AceFlag flag : ace.getFlags()) {
            LOG.debug(" - {}", flag);
        }

        int aceSize = ace.getSize();
        LOG.debug("Ace Size (bytes): {}", aceSize);

        LOG.debug("Ace Rights: ");
        for (AceRights.ObjectRight right : ace.getRights().getObjectRights()) {
            LOG.debug(" - {}", right.name());
        }

        if (ace.getRights().getOthers() != 0) {
            LOG.debug(" - OTHERS({})", Hex.get(NumberFacility.getUIntBytes(ace.getRights().getOthers())));
        }

        if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
            LOG.debug("Flags: ");
            for (AceObjectFlags.Flag flag : ace.getObjectFlags().getFlags()) {
                LOG.debug(" - {}", flag.name());
            }

            if (ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                LOG.debug("ObjectType: {}", GUID.getGuidAsString(ace.getObjectType()));
            }

            if (ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                LOG.debug("InheritedObjectType: {}", GUID.getGuidAsString(ace.getInheritedObjectType()));
            }
        }

        final SID sid = ace.getSid();
        printSID(sid);

        if (ace.getApplicationData() != null && ace.getApplicationData().length > 0) {
            LOG.debug("Application data: " + Hex.get(ace.getApplicationData()));
        }
    }
}
