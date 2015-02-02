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
package net.tirasa.adsddl.unit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
import org.junit.Assert;
import org.junit.BeforeClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractTest {

    private static final long serialVersionUID = 1L;

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(AbstractTest.class);

    protected static final String SDDL_ALL_SAMPLE = "/sddlSample.bin";

    protected static final String DACL_ONLY_SAMPLE = "/daclOnlySample.bin";

    protected static String[] control = {
        "SR", "RM", "PS", "PD", "SI", "DI", "SC", "DC", "DT", "SS", "SD", "SP", "DD", "DP", "GD", "OD" };

    @BeforeClass
    @SuppressWarnings("unchecked")
    public static void setUpConnection() throws IOException {
        // nothing to set up
    }

    protected void UnMarshall(final byte[] src) throws Exception {
        final SDDL sddl = new SDDL(src);

        if (log.isDebugEnabled()) {
            printSDDL(sddl);
            log.info(sddl.toString());
        }

        Assert.assertTrue(sddl.equals(new SDDL(sddl.toByteArray())));
    }

    protected void UserChangePassword(final byte[] src) throws Exception {
        final SDDL sddl = new SDDL(src);

        if (log.isDebugEnabled()) {
            printSDDL(sddl);
            log.info(sddl.toString());
        }

        Assert.assertTrue(Arrays.equals(src, sddl.toByteArray()));

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

        if (log.isDebugEnabled()) {
            printSDDL(sddl);
            log.info(sddl.toString());
        }

        Assert.assertTrue(Arrays.equals(src, sddl.toByteArray()));

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

        Assert.assertFalse(Arrays.equals(src, sddl.toByteArray()));
    }

    protected void printSDDL(final SDDL sddl) {
        log.debug("Revision: {}", Hex.get(sddl.getRevision()));

        log.debug("Control flags: ");
        final boolean[] controlFlag = NumberFacility.getBits(sddl.getControlFlags());

        int count = 0;
        for (boolean flag : controlFlag) {
            if (flag) {
                log.debug(" - {}", control[count]);
            }
            count++;
        }

        // retrieve owner sid
        final SID owner = sddl.getOwner();
        if (owner != null) {
            log.debug("Owner SID: ....");
            printSID(owner);
        }

        // retrieve owner sid
        final SID group = sddl.getGroup();
        if (group != null) {
            log.debug("Group SID: ....");
            printSID(group);
        }

        final ACL sacl = sddl.getSacl();
        if (sacl != null) {
            log.debug("------------------------------------------");
            log.debug("SACL ");
            log.debug("------------------------------------------");

            printACL(sacl);
        }

        final ACL dacl = sddl.getDacl();
        if (dacl != null) {
            log.debug("------------------------------------------");
            log.debug("DACL ");
            log.debug("------------------------------------------");

            printACL(dacl);
        }
    }

    protected void printACL(final ACL acl) {

        log.debug("Acl Revision: {}", acl.getRevision().name());
        log.debug("Acl Size (bytes): {}", acl.getSize());

        int aceCount = acl.getAceCount();
        log.debug("Ace Count: {}", aceCount);

        for (int i = 0; i < aceCount; i++) {
            log.debug("------------------------------------------");
            log.debug("ACE " + i);
            log.debug("------------------------------------------");
            final ACE ace = acl.getAce(i);
            printACE(ace);
        }
    }

    protected void printSID(final SID sid) {
        log.debug("SID Revision: {}", Hex.get(sid.getRevision()));

        int subAuthCount = sid.getSubAuthorityCount();
        log.debug("SID Sub Authorities Count: {}", subAuthCount);
        log.debug("SID Identifier Authority: {}", Hex.get(sid.getIdentifierAuthority()));
        log.debug("SID Sub Authorities: ");
        for (byte[] sub : sid.getSubAuthorities()) {
            log.debug(" - {}", Hex.get(sub));
        }
    }

    protected void printACE(final ACE ace) {
        log.debug("AceType: {}", ace.getType().name());
        log.debug("AceFlags: ");
        for (AceFlag flag : ace.getFlags()) {
            log.debug(" - {}", flag);
        }

        int aceSize = ace.getSize();
        log.debug("Ace Size (bytes): {}", aceSize);

        log.debug("Ace Rights: ");
        for (AceRights.ObjectRight right : ace.getRights().getObjectRights()) {
            log.debug(" - {}", right.name());
        }

        if (ace.getRights().getOthers() != 0) {
            log.debug(" - OTHERS({})", Hex.get(NumberFacility.getUIntBytes(ace.getRights().getOthers())));
        }

        if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
            log.debug("Flags: ");
            for (AceObjectFlags.Flag flag : ace.getObjectFlags().getFlags()) {
                log.debug(" - {}", flag.name());
            }

            if (ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                log.debug("ObjectType: {}", GUID.getGuidAsString(ace.getObjectType()));
            }

            if (ace.getObjectFlags().getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                log.debug("InheritedObjectType: {}", GUID.getGuidAsString(ace.getInheritedObjectType()));
            }
        }

        final SID sid = ace.getSid();
        printSID(sid);

        if (ace.getApplicationData().length > 0) {
            log.debug("Application data: " + Hex.get(ace.getApplicationData()));
        }
    }
}
