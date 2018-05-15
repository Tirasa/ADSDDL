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
package net.tirasa.adsddl.ntsd.utils;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Utility class to manage GUID.
 * A GUID, also known as a UUID, is a 16-byte structure, intended to serve as a unique identifier for an object. There
 * are three representations of a GUID, as described in the following sections.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc230326.aspx
 */
public class GUID {

    /**
     * Gets GUID as string.
     *
     * @param GUID GUID.
     * @return GUID as string.
     */
    public static String getGuidAsString(byte[] GUID) {
        final StringBuilder res = new StringBuilder();

        res.append(AddLeadingZero((int) GUID[3] & 0xFF));
        res.append(AddLeadingZero((int) GUID[2] & 0xFF));
        res.append(AddLeadingZero((int) GUID[1] & 0xFF));
        res.append(AddLeadingZero((int) GUID[0] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[5] & 0xFF));
        res.append(AddLeadingZero((int) GUID[4] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[7] & 0xFF));
        res.append(AddLeadingZero((int) GUID[6] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[8] & 0xFF));
        res.append(AddLeadingZero((int) GUID[9] & 0xFF));
        res.append("-");
        res.append(AddLeadingZero((int) GUID[10] & 0xFF));
        res.append(AddLeadingZero((int) GUID[11] & 0xFF));
        res.append(AddLeadingZero((int) GUID[12] & 0xFF));
        res.append(AddLeadingZero((int) GUID[13] & 0xFF));
        res.append(AddLeadingZero((int) GUID[14] & 0xFF));
        res.append(AddLeadingZero((int) GUID[15] & 0xFF));

        return res.toString();

    }

    /**
     * Gets GUID as byte array.
     *
     * @param GUID GUID.
     * @return GUID as byte array.
     */
    public static byte[] getGuidAsByteArray(final String GUID) {
        final UUID uuid = UUID.fromString(GUID);

        final ByteBuffer buff = ByteBuffer.wrap(new byte[16]);
        buff.putLong(uuid.getMostSignificantBits());
        buff.putLong(uuid.getLeastSignificantBits());

        byte[] res = new byte[] {
            buff.get(3),
            buff.get(2),
            buff.get(1),
            buff.get(0),
            buff.get(5),
            buff.get(4),
            buff.get(7),
            buff.get(6),
            buff.get(8),
            buff.get(9),
            buff.get(10),
            buff.get(11),
            buff.get(12),
            buff.get(13),
            buff.get(14),
            buff.get(15), };

        return res;
    }

    private static String AddLeadingZero(int k) {
        return (k <= 0xF) ? "0" + Integer.toHexString(k) : Integer.toHexString(k);
    }
}
