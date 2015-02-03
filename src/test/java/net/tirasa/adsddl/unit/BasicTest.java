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
package net.tirasa.adsddl.unit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;
import org.junit.Test;

public class BasicTest {

    private static final byte[] guid = new byte[] {
        (byte) 0x53,
        (byte) 0x1A,
        (byte) 0x72,
        (byte) 0xAB,
        (byte) 0x2F,
        (byte) 0x1E,
        (byte) 0xD0,
        (byte) 0x11,
        (byte) 0x98,
        (byte) 0x19,
        (byte) 0x00,
        (byte) 0xAA,
        (byte) 0x00,
        (byte) 0x40,
        (byte) 0x52,
        (byte) 0x9B };

    @Test
    public void guid() {
        assertTrue(Arrays.equals(GUID.getGuidAsByteArray(SDDLHelper.UCP_OBJECT_GUID), guid));
        assertEquals(SDDLHelper.UCP_OBJECT_GUID, GUID.getGuidAsString(guid));
    }

    @Test
    public void checkInt() {
        // check for max int
        byte[] max = NumberFacility.getBytes(Integer.MAX_VALUE);
        long value = NumberFacility.getUInt(max);
        assertEquals((long) Integer.MAX_VALUE, value, 0);
        assertTrue(Arrays.equals(max, NumberFacility.getUIntBytes(value)));
        assertEquals(Integer.MAX_VALUE, NumberFacility.getInt(max));

        // check for max int + 1
        max = NumberFacility.getUIntBytes(Integer.MAX_VALUE + 1);
        value = NumberFacility.getUInt(max);
        assertEquals((long) Integer.MAX_VALUE + 1, value, 0);
        assertTrue(NumberFacility.getInt(max) < 0);
        assertTrue(Arrays.equals(max, NumberFacility.getUIntBytes(value)));
        assertNotEquals((long) Integer.MAX_VALUE + 1, NumberFacility.getInt(max), 0);
        assertEquals(Integer.MAX_VALUE + 1, NumberFacility.getInt(max), 0);

        for (long i = 1; i < Integer.MAX_VALUE;) {
            assertEquals(i, NumberFacility.getInt(NumberFacility.getBytes((int) i)), 0);

            final long l = i * 2l;
            assertEquals(l, NumberFacility.getUInt(NumberFacility.getUIntBytes(l)), 0);

            i += 98765;
        }
    }
}
