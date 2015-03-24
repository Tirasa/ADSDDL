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

/**
 * Utility class to be used to convert byte arrays into hexadecimal strings.
 */
public class Hex {

    /**
     * Gets hex string corresponding to the given byte array from "<tt>from</tt>" position to "<tt>to's</tt>"
     *
     * @param bytes bytes.
     * @param from from position.
     * @param to to position.
     * @return hex string.
     */
    public static String get(byte[] bytes, int from, int to) {
        final StringBuilder bld = new StringBuilder();
        for (int i = from; i < to; i++) {
            bld.append(Hex.get(bytes[i]));
        }
        return bld.toString();
    }

    /**
     * Gets hex string corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return hex string.
     */
    public static String get(byte... bytes) {
        final StringBuilder bld = new StringBuilder();
        for (byte b : bytes) {
            bld.append(Hex.get(b));
        }
        return bld.toString();
    }

    /**
     * Gets escaped hex string corresponding to the given bytes.
     *
     * @param bytes bytes.
     * @return escaped hex string
     */
    public static String getEscaped(byte... bytes) {
        final StringBuilder bld = new StringBuilder();
        for (byte b : bytes) {
            bld.append("\\").append(Hex.get(b));
        }
        return bld.toString();
    }

    /**
     * Gets hex string corresponding to the given byte.
     *
     * @param b byte.
     * @return hex string.
     */
    public static String get(byte b) {
        return String.format("%02X", b);
    }

    /**
     * Reverses bytes.
     *
     * @param bytes bytes.
     * @return reversed byte array.
     */
    public static byte[] reverse(byte... bytes) {
        byte[] res = new byte[bytes.length];
        int j = 0;
        for (int i = bytes.length - 1; i >= 0; i--) {
            res[j] = bytes[i];
            j++;
        }
        return res;
    }
}
