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
 * An unsigned 8-bit integer that specifies a set of ACE type-specific control flags.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc230296.aspx.
 */
public enum AceFlag {

    /**
     * 0x02 - Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited
     * ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
     */
    CONTAINER_INHERIT_ACE((byte) 0x02, "CI"),
    /**
     * 0x80 - Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed
     * access attempts.
     */
    FAILED_ACCESS_ACE_FLAG((byte) 0x80, "FA"),
    /**
     * 0x08 - Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If
     * this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached.
     *
     * Both effective and inherit-only ACEs can be inherited depending on the state of the other inheritance flags.
     */
    INHERIT_ONLY_ACE((byte) 0x08, "IO"),
    /**
     * 0x10 - Indicates that the ACE was inherited. The system sets this bit when it propagates an inherited ACE to a
     * child object.
     */
    INHERITED_ACE((byte) 0x10, "ID"),
    /**
     * 0x04 - If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and
     * CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent
     * generations of objects.
     */
    NO_PROPAGATE_INHERIT_ACE((byte) 0x04, "NP"),
    /**
     * 0x01 - Noncontainer child objects inherit the ACE as an effective ACE.
     *
     * For child objects that are containers, the ACE is inherited as an inherit-only ACE unless the
     * NO_PROPAGATE_INHERIT_ACE bit flag is also set.
     */
    OBJECT_INHERIT_ACE((byte) 0x01, "OI"),
    /**
     * 0x40 - Used with system-audit ACEs in a SACL to generate audit messages for successful access attempts.
     */
    SUCCESSFUL_ACCESS_ACE_FLAG((byte) 0x40, "SA");

    private final byte value;

    private final String str;

    /**
     * Private constructor.
     *
     * @param value byte value.
     * @param str string value.
     */
    private AceFlag(final byte value, final String str) {
        this.value = value;
        this.str = str;
    }

    /**
     * Gets byte value.
     *
     * @return byte value.
     */
    public byte getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     *
     * @return string value.
     */
    @Override
    public String toString() {
        return str;
    }

    /**
     * Parse byte value.
     *
     * @param value byte value.
     * @return ACE flags.
     */
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
