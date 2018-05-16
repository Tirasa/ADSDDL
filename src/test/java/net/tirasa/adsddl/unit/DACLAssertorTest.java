/*
 * Copyright (C) 2018 VMware, Inc.
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
/*
 * Copyright © 2018 VMware, Inc. All Rights Reserved.
 *
 * COPYING PERMISSION STATEMENT
 * SPDX-License-Identifier: Apache-2.0
 */
package net.tirasa.adsddl.unit;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.naming.NamingException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.tirasa.adsddl.ntsd.dacl.AceAssertion;
import net.tirasa.adsddl.ntsd.dacl.DACLAssertor;
import net.tirasa.adsddl.ntsd.dacl.DomainJoinRoleAssertion;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;

public class DACLAssertorTest {

    private static final Logger logger = LoggerFactory.getLogger(DACLAssertorTest.class);

    private SDDL sddl;
    private final String userSIDStr = "S-1-5-21-1835709989-2027683138-697581538-1139";
    private SID userSID;
    private final String[] groupSIDStr = { "S-1-5-21-1835709989-2027683138-697581538-1440",
            "S-1-5-21-1835709989-2027683138-697581538-1107", "S-1-5-21-1835709989-2027683138-697581538-513" };
    private final List<String> groupSIDList = Arrays.asList(groupSIDStr);

    @Before
    public void setUp() throws IOException, URISyntaxException {
        final byte[] src = Files.readAllBytes(Paths.get(this.getClass().getResource("/sddlSampleForAssertor.bin").toURI()));
        String hexString = javax.xml.bind.DatatypeConverter.printHexBinary(src);
        logger.debug("SDDL hexDump: {}", hexString);

        this.sddl = new SDDL(src);
        userSID = SID.parse(getSidAsByteBuffer(userSIDStr).array());
    }

    private ByteBuffer getSidAsByteBuffer(String strSID) {
        ByteBuffer bb = ByteBuffer.allocate(256);

        if (strSID != null) {
            String[] comp = strSID.split("-");
            int count = comp.length;

            if (count > 3) {
                byte version = Byte.parseByte(comp[1]);
                bb.put(version);

                bb.put((byte) ((count - 3) & 0xFF));

                long authority = Long.parseLong(comp[2]);
                bb.put(getLongAsByteBuffer(authority, ByteOrder.BIG_ENDIAN, 6));

                for (int i = 3; i < count; i++) {
                    long val = Long.parseLong(comp[i]);
                    bb.put(getLongAsByteBuffer(val, ByteOrder.LITTLE_ENDIAN, 4));
                }
            }
        }

        bb.flip();
        return bb;
    }

    /**
     * Convert a long to ByteBuffer, in little/big endian byte order, keeping byteCount bytes only
     */
    private ByteBuffer getLongAsByteBuffer(long val, ByteOrder order, int byteCount) {
        ByteBuffer lb = ByteBuffer.allocate(8);
        lb.order(order);
        lb.putLong(val);
        if (order == ByteOrder.BIG_ENDIAN) {
            lb.position(8 - byteCount);
        } else {
            lb.position(byteCount);
            lb.flip();
        }
        return lb;
    }

    @Test
    public void testDomainJoinRoleNegative() throws NamingException {
        // This should test negatively because the userSID is only granted one of the permissions (create computer)
        // and this test tells the assertor to NOT search groups.
        ACL dacl = sddl.getDacl();
        DACLAssertor assertor = new DACLAssertor(dacl, false);

        DomainJoinRoleAssertion djAssertion = new DomainJoinRoleAssertion(userSID, false, null);
        boolean result = assertor.doAssert(djAssertion);
        Assert.assertFalse(result);

        // should be 6 of them
        List<AceAssertion> unsatisfiedAssertions = assertor.getUnsatisfiedAssertions();
        Assert.assertEquals(6, unsatisfiedAssertions.size());
    }

    @Test
    public void testDomainJoinRolePositive() throws NamingException {
        // This should test positively because while the userSID is only granted one of the permissions (create computer),
        // the group SID ending with "-1440" has all of them, and the assertor will search groups.
        ACL dacl = sddl.getDacl();
        DACLAssertor assertor = new DACLAssertor(dacl, true);

        List<SID> groupSIDs = new ArrayList<>();
        for (String s : groupSIDList) {
            groupSIDs.add(SID.parse(getSidAsByteBuffer(s).array()));
        }
        logger.debug("groupSIDs: {}", groupSIDs);
        DomainJoinRoleAssertion djAssertion = new DomainJoinRoleAssertion(userSID, false, groupSIDs);
        boolean result = assertor.doAssert(djAssertion);
        Assert.assertTrue(result);
    }
}
