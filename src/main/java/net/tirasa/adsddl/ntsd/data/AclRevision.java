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
package net.tirasa.adsddl.ntsd.data;

/**
 * An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported for
 * on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the wire.
 * Therefore this field MUST be set to one of the following values.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc230297.aspx
 */
public enum AclRevision {

    /**
     * Unknown.
     */
    UNEXPECTED((byte) 0x00),
    /**
     * 0x02 - When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, and 0x11 can be present in the ACL. An AceType of
     * 0x11 is used for SACLs but not for DACLs.
     */
    ACL_REVISION((byte) 0x02),
    /**
     * 0x04 - When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are
     * applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
     */
    ACL_REVISION_DS((byte) 0x04);

    /**
     * byte value.
     */
    private final byte value;

    /**
     * Private constructor.
     *
     * @param value byte value.
     */
    private AclRevision(byte value) {
        this.value = value;
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
     * Parse byte value.
     *
     * @param value byet value.
     * @return ACL revision.
     */
    public static AclRevision parseValue(final byte value) {
        for (AclRevision type : AclRevision.values()) {
            if (type.getValue() == value) {
                return type;
            }
        }

        return UNEXPECTED;
    }
}
