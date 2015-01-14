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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;
import org.junit.Assert;
import org.junit.Test;

public class RetrieveTest extends AbstractTest {

    private static final long serialVersionUID = 1L;

    @Test
    public void UnMarshall() throws Exception {
        final byte[] src = Files.readAllBytes(Paths.get(this.getClass().getResource(SDDL_ALL_SAMPLE).toURI()));

        final SDDL sddl = new SDDL(src);

        if (log.isDebugEnabled()) {
            printSDDL(sddl);
        }

        final byte[] marshalled = sddl.toByteArray();

        Assert.assertTrue(Arrays.equals(src, marshalled));
    }

    @Test
    public void UserChangePasswordTest() throws Exception {
        final byte[] src = Files.readAllBytes(Paths.get(this.getClass().getResource(DACL_ONLY_SAMPLE).toURI()));

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

    @Test
    public void ucpChangeUnMarshallTest() throws Exception {
        final byte[] src = Files.readAllBytes(Paths.get(this.getClass().getResource(DACL_ONLY_SAMPLE).toURI()));

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
