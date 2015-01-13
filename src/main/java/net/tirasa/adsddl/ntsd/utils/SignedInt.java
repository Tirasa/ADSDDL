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

package net.tirasa.adsddl.ntsd.utils;

import java.nio.ByteBuffer;
import java.security.InvalidParameterException;

public class SignedInt {

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

    public static boolean[] getBits(final int value) {
        final boolean[] res = new boolean[32];
        for (int i = 0; i < 32; i++) {
            res[31 - i] = (value & (1 << i)) != 0;
        }
        return res;
    }

    public static int getReverseInt(final byte... bytes) {
        return getInt(Hex.reverse(bytes));
    }

    public static int getInt(final byte... bytes) {
        if (bytes.length > 4) {
            throw new InvalidParameterException("Invalid number of bytes");
        }

        return getInt(getBits(bytes));
    }

    public static int getInt(final boolean[] bits) {
        if (bits.length > 32) {
            throw new InvalidParameterException("Invalid number of bits");
        }

        final boolean[] toBeProcessed = new boolean[32];
        System.arraycopy(bits, 0, toBeProcessed, 32 - bits.length, bits.length);

        int res = 0;

        int pow = 31;
        for (boolean bit : toBeProcessed) {
            if (bit) {
                res += Math.pow(2, pow);
            }
            pow--;
        }

        return res;
    }

    public static String toString(boolean[] bits) {
        if (bits.length > 32) {
            throw new InvalidParameterException("Invalid number of bits");
        }

        final StringBuilder builder = new StringBuilder(32);
        for (boolean bit : bits) {
            builder.append(bit ? 1 : 0);
        }
        return builder.toString();
    }
}
