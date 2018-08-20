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
import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Utility class to be used to manipulate byte arrays and numbers.
 */
public class NumberFacility {

    /**
     * Gets byte array corresponding to a given unsigned integer.
     *
     * @param value unsigned integer.
     * @return byte array.
     */
    public static byte[] getUIntBytes(final long value) {
        return Arrays.copyOfRange(ByteBuffer.allocate(8).putLong(value).array(), 4, 8);
    }

    /**
     * Gets byte array from integer.
     *
     * @param value integer.
     * @return byte array.
     */
    public static byte[] getBytes(final int value) {
        return ByteBuffer.allocate(4).putInt(value).array();
    }
    
    /**
     * Gets byte array from integer.
     *
     * @param value integer.
     * @param length array size.
     * @return byte array.
     */
    public static byte[] getBytes(final int value, final int length) {
        return ByteBuffer.allocate(length).putInt(value).array();
    }

    /**
     * Remove 0x00 bytes from left side.
     *
     * @param bytes source array.
     * @return trimmed array.
     */
    @SuppressWarnings("empty-statement")
    public static byte[] leftTrim(final byte... bytes) {
        int pos = 0;
        for (; pos < bytes.length && bytes[pos] == 0x00; pos++);

        if (pos < bytes.length) {
            return Arrays.copyOfRange(bytes, pos, bytes.length);
        } else {
            return new byte[] { 0x00 };
        }
    }

    /**
     * Remove 0x00 bytes from right side.
     *
     * @param bytes source array.
     * @return trimmed array.
     */
    public static byte[] rightTrim(final byte... bytes) {
        return Hex.reverse(leftTrim(Hex.reverse(bytes)));
    }

    /**
     * Gets bits as boolean array from a given byte array.
     *
     * @param bytes bytes.
     * @return bits.
     */
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

    /**
     * Gets bits as boolean array from a given byte.
     *
     * @param b byte.
     * @return bits.
     */
    public static boolean[] getBits(final byte b) {
        final boolean[] res = new boolean[8];
        for (int i = 0; i < 8; i++) {
            res[7 - i] = (b & (1 << i)) != 0;
        }
        return res;
    }

    /**
     * Reverts bytes and retrieves the corresponding integer value.
     *
     * @param bytes bytes.
     * @return integer.
     */
    public static int getReverseInt(final byte... bytes) {
        return (int) getReverseUInt(bytes);
    }

    /**
     * Reverses bytes and retrieves the corresponding unsigned integer value.
     *
     * @param bytes bytes.
     * @return unsigned integer.
     */
    public static long getReverseUInt(final byte... bytes) {
        return getUInt(Hex.reverse(bytes));
    }

    /**
     * Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
     * integer value.
     *
     * @param value integer value.
     * @return reversed integer value.
     */
    public static int getReverseInt(final int value) {
        return (int) getReverseUInt(value);
    }

    /**
     * Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
     * unsigned integer value.
     *
     * @param value integer value.
     * @return reversed unsigned integer value.
     */
    public static long getReverseUInt(final int value) {
        return getReverseUInt(getBytes(value));
    }

    /**
     * Gets integer value corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return integer.
     */
    public static int getInt(final byte... bytes) {
        return (int) getUInt(bytes);
    }

    /**
     * Gets unsigned integer value corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return unsigned integer.
     */
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
