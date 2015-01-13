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

import java.util.Arrays;

public class Unit {

    private final byte[] bytes;

    private final boolean[] bits;

    private int value;

    public Unit() {
        bytes = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        bits = new boolean[32];
    }

    public Unit(int value) {
        this.value = value;
        bytes = SignedInt.getBytes(this.value);
        bits = SignedInt.getBits(value);
    }

    public Unit(final byte b1, final byte b2, final byte b3, final byte b4) {
        bytes = new byte[] { b1, b2, b3, b4 };
        bits = SignedInt.getBits(bytes);
        value = SignedInt.getInt(bits);
    }

    public boolean[] getBits() {
        return Arrays.copyOf(bits, bits.length);
    }

    public boolean[] getBits(final int from, final int to) {
        return Arrays.copyOfRange(
                bits, from >= bytes.length ? bits.length : from * 8, to >= bytes.length ? bits.length : to * 8);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    public byte[] getBytes(final int from, final int to) {
        return Arrays.copyOfRange(
                bytes, from >= bytes.length ? bytes.length : from, to >= bytes.length ? bytes.length : to);
    }

    public int getValue() {
        return value;
    }

    public String toString(final int from, final int to) {
        return SignedInt.toString(getBits(from, to));
    }
}
