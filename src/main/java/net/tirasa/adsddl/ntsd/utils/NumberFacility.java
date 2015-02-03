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
package net.tirasa.adsddl.ntsd.utils;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.Arrays;

public class NumberFacility {

    public static byte[] getUIntBytes(final long value) {
        return Arrays.copyOfRange(ByteBuffer.allocate(8).putLong(value).array(), 4, 8);
    }

    public static byte[] getBytes(final int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    public static boolean[] getBits(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }

        final boolean[] res = new boolean[bytes.length * 8];

        int pos = 0;

        for (byte b : bytes) {
            for (boolean bool : getBits(b)) {
                res[pos] = bool;
                pos++;
            }
        }

        return res;
    }

    public static boolean[] getBits(final byte b) {
        final boolean[] res = new boolean[8];
        for (int i = 0; i < 8; i++) {
            res[7 - i] = (b & (1 << i)) != 0;
        }
        return res;
    }

    public static int getReverseInt(final byte... bytes) {
        return (int) getReverseUInt(bytes);
    }

    public static long getReverseUInt(final byte... bytes) {
        return getUInt(Hex.reverse(bytes));
    }

    public static int getReverseInt(final int value) {
        return (int) getReverseUInt(value);
    }

    public static long getReverseUInt(final int value) {
        return getReverseUInt(getBytes(value));
    }

    public static int getInt(final byte... bytes) {
        return (int) getUInt(bytes);
    }

    public static long getUInt(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }

        long res = 0;
        for (int i = 0; i < bytes.length; i++) {
            res |= bytes[i] & 0xFF;
            if (i < bytes.length - 1) {
                res <<= 8;
            }
        }

        return res;
    }
}
