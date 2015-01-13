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

public enum AceFlag {

    CONTAINER_INHERIT_ACE((byte) 0x02, "CI"),
    FAILED_ACCESS_ACE_FLAG((byte) 0x80, "FA"),
    INHERIT_ONLY_ACE((byte) 0x08, "IO"),
    INHERITED_ACE((byte) 0x10, "ID"),
    NO_PROPAGATE_INHERIT_ACE((byte) 0x04, "NP"),
    OBJECT_INHERIT_ACE((byte) 0x01, "OI"),
    SUCCESSFUL_ACCESS_ACE_FLAG((byte) 0x40, "SA");

    private final byte value;

    private final String str;

    private AceFlag(final byte value, final String str) {
        this.value = value;
        this.str = str;
    }

    public byte getValue() {
        return value;
    }

    @Override
    public String toString() {
        return str;
    }

    public static List<AceFlag> parseValue(final byte value) {
        final List<AceFlag> res = new ArrayList<>();
        
        for (AceFlag type : AceFlag.values()) {
            if ((value & type.getValue()) == type.getValue()) {
                res.add(type);
            }
        }

        return res;
    }
}
