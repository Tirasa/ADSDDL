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
package net.tirasa.adsddl.ntsd.data;

import java.util.ArrayList;
import java.util.List;

public class AceObjectFlags {

    public static enum Flag {

        ACE_OBJECT_TYPE_PRESENT(0x00000001),
        ACE_INHERITED_OBJECT_TYPE_PRESENT(0x00000002);

        private final int value;

        private Flag(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    private final List<Flag> flags = new ArrayList<>();

    private int others = 0;

    public AceObjectFlags(final Flag... fls) {
        for (Flag flag : fls) {
            if (!flags.contains(flag)) {
                flags.add(flag);
            }
        }
    }

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

    public List<Flag> getFlags() {
        return flags;
    }

    public AceObjectFlags addFlag(final Flag flag) {
        if (!flags.contains(flag)) {
            flags.add(flag);
        }
        return this;
    }

    public long getOthers() {
        return others;
    }

    public AceObjectFlags setOthers(int others) {
        this.others = others;
        return this;
    }

    public long asUInt() {
        long res = others;

        for (AceObjectFlags.Flag flag : flags) {
            res += flag.getValue();
        }

        return res;
    }
}
