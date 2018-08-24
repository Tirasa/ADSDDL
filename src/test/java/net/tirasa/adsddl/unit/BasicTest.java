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

import static net.tirasa.adsddl.unit.AbstractTest.SDDL_ALL_SAMPLE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.controls.DirSyncControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;
import org.junit.Test;

public class BasicTest {

    private static final byte[] OBJECT_GUID = new byte[] {
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
        assertTrue(Arrays.equals(GUID.getGuidAsByteArray(SDDLHelper.UCP_OBJECT_GUID), OBJECT_GUID));
        assertEquals(SDDLHelper.UCP_OBJECT_GUID, GUID.getGuidAsString(OBJECT_GUID));
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

    @Test
    public void sddlToString() throws IOException, URISyntaxException {
        final byte[] src = Files.readAllBytes(Paths.get(this.getClass().getResource(SDDL_ALL_SAMPLE).toURI()));
        final SDDL sddl = new SDDL(src);

        // TODO: complete sddl string representation check
    }

    @Test
    public void trim() {
        int src = 0x00010200;
        byte[] actual = NumberFacility.leftTrim(NumberFacility.getBytes(src));
        assertEquals("010200", Hex.get(actual));
        actual = NumberFacility.rightTrim(NumberFacility.getBytes(src));
        assertEquals("000102", Hex.get(actual));

        src = 0x00000000;
        actual = NumberFacility.leftTrim(NumberFacility.getBytes(src));
        assertEquals("00", Hex.get(actual));
        actual = NumberFacility.rightTrim(NumberFacility.getBytes(src));
        assertEquals("00", Hex.get(actual));
    }

    @Test
    public void berEncoding() {
        try {

            final String cookie = "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on"
                    + "test dir sync control against buffer overflow exceptions and so on";

            final int expectedValueSize = 16 + 2 + 2 + cookie.length();

            final byte[] value = new DirSyncControl(cookie.getBytes()).getEncodedValue();

            assertEquals(expectedValueSize, value.length);

            assertEquals((byte) 0x30, value[0]);
            assertEquals((byte) 0x82, value[1]); // long form
            assertEquals((byte) 0x02, value[4]);
            assertEquals((byte) 0x04, value[5]);
            assertEquals((byte) 0x82, value[17]); // long form

            assertEquals('n', value[expectedValueSize - 1]);
        } catch (Exception ex) {
            Logger.getLogger(BasicTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
