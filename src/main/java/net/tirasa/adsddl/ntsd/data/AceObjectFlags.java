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
package net.tirasa.adsddl.ntsd.data;

import java.util.ArrayList;
import java.util.List;

/**
 * A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
 * InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230289.aspx" target="_top">cc230289</a>
 */
public class AceObjectFlags {

    /**
     * ACE object flag.
     */
    public static enum Flag {

        /**
         * 0x00000001 - ObjectType is valid.
         */
        ACE_OBJECT_TYPE_PRESENT(0x00000001),
        /**
         * 0x00000002 - InheritedObjectType is valid. If this value is not specified, all types of child objects can
         * inherit the ACE.
         */
        ACE_INHERITED_OBJECT_TYPE_PRESENT(0x00000002);

        /**
         * Int value.
         */
        private final int value;

        /**
         * Private constructor.
         *
         * @param value int value.
         */
        private Flag(int value) {
            this.value = value;
        }

        /**
         * Gets int value.
         *
         * @return int value.
         */
        public int getValue() {
            return value;
        }
    }

    /**
     * Standard flags.
     */
    private final List<Flag> flags = new ArrayList<>();

    /**
     * Custom/Other flags.
     */
    private int others = 0;

    /**
     * Constructor.
     *
     * @param fls ACE object flags.
     */
    public AceObjectFlags(final Flag... fls) {
        for (Flag flag : fls) {
            if (!flags.contains(flag)) {
                flags.add(flag);
            }
        }
    }

    /**
     * Parse flags given as int value.
     *
     * @param value flags given as int value.
     * @return ACE object flags.
     */
    public static AceObjectFlags parseValue(final int value) {
        final AceObjectFlags res = new AceObjectFlags();

        res.others = value;

        for (AceObjectFlags.Flag type : AceObjectFlags.Flag.values()) {
            if ((value & type.getValue()) == type.getValue()) {
                res.flags.add(type);
                res.others ^= type.getValue();
            }
        }

        return res;
    }

    /**
     * Gets standard ACE object flags.
     *
     * @return stabdatd ACE object flags.
     */
    public List<Flag> getFlags() {
        return flags;
    }

    /**
     * Adds standard ACE object flag.
     *
     * @param flag standard ACE object flag.
     * @return the current ACE object flags.
     */
    public AceObjectFlags addFlag(final Flag flag) {
        if (!flags.contains(flag)) {
            flags.add(flag);
        }
        return this;
    }

    /**
     * Gets custom/other ACE object flags.
     *
     * @return custom/other ACE object flags as long value.
     */
    public long getOthers() {
        return others;
    }

    /**
     * Sets custom/others ACE object flags.
     *
     * @param others custom/other ACE object flags given as int value..
     * @return the current ACE object flags.
     */
    public AceObjectFlags setOthers(int others) {
        this.others = others;
        return this;
    }

    /**
     * Gets custom/other ACE object flags as long value.
     *
     * @return custom/other ACE object flags as long value.
     */
    public long asUInt() {
        long res = others;

        for (AceObjectFlags.Flag flag : flags) {
            res += flag.getValue();
        }

        return res;
    }
}
