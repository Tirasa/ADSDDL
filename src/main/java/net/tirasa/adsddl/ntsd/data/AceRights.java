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
 * An ACCESS_MASK that specifies the user rights allowed by this ACE.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230289.aspx" target="_top">cc230289</a>
 */
public class AceRights {

    /**
     * Standard ACE rights.
     */
    public static enum ObjectRight {

        /**
         * GENERIC_READ - When read access to an object is requested, this bit is translated to a combination of bits.
         * These are most often set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) The bits that are set are implementation dependent. During this
         * translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * checked against the ACE structures in the security descriptor that attached to the object.
         *
         * When the GR bit is set in an ACE that is to be attached to an object, it is translated into a combination of
         * bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) The bits that are set are implementation dependent. During this
         * translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * granted by this ACE.
         */
        GR(0x80000000),
        /**
         * GENERIC_WRITE - When write access to an object is requested, this bit is translated to a combination of bits,
         * which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) The bits that are set are implementation dependent. During this
         * translation, the GW bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * checked against the ACE structures in the security descriptor that attached to the object.
         *
         * When the GW bit is set in an ACE that is to be
         * attached to an object, it is translated into a combination of bits, which are usually set in the lower 16
         * bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits
         * that are set are implementation dependent. During this translation, the GW bit is cleared. The resulting
         * ACCESS_MASK bits are the actual permissions that are granted by this ACE.
         */
        GW(0x40000000),
        /**
         * GENERIC_EXECUTE - When execute access to an object is requested, this bit is translated to a combination of
         * bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) The bits that are set are implementation dependent. During this
         * translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * checked against the ACE structures in the security descriptor that attached to the object.
         *
         * When the GX bit is set in an ACE that is to be attached to an object, it is translated into a combination of
         * bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) The bits that are set are implementation dependent. During this
         * translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * granted by this ACE.
         */
        GX(0x20000000),
        /**
         * GENERIC_ALL - When all access permissions to an object are requested, this bit is translated to a combination
         * of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications
         * MAY specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
         * translation as required by the objects semantics. The bits that are set are implementation dependent. During
         * this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
         * checked against the ACE structures in the security descriptor that attached to the object.
         *
         * When the GA bit is set in an ACE that is to be attached to an object, it is translated into a combination of
         * bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
         * specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
         * translation, if required by the objects semantics. The bits that are set are implementation dependent.
         * During this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions
         * that are granted by this ACE.
         */
        GA(0x10000000),
        /**
         * MAXIMUM_ALLOWED - When requested, this bit grants the requestor the maximum permissions allowed to the
         * object through the Access Check Algorithm. This bit can only be requested; it cannot be set in an ACE.
         *
         * Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
         * and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
         */
        MA(0x02000000),
        /**
         * ACCESS_SYSTEM_SECURITY - When requested, this bit grants the requestor the maximum permissions allowed to the
         * object through the Access Check Algorithm. This bit can only be requested; it cannot be set in an ACE.
         *
         * Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
         * and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
         */
        AS(0x01000000),
        /**
         * SYNCHRONIZE - Specifies access to the object sufficient to synchronize or wait on the object.
         */
        SY(0x00100000),
        /**
         * WRITE_OWNER - Specifies access to change the owner of the object as listed in the security descriptor.
         */
        WO(0x00080000),
        /**
         * WRITE_DACL - Specifies access to change the discretionary access control list of the security descriptor of
         * an object.
         */
        WD(0x00040000),
        /**
         * READ_CONTROL - Specifies access to read the security descriptor of an object.
         */
        RC(0x00020000),
        /**
         * DELETE - Specifies access to delete an object.
         */
        SD(0x00010000),
        /**
         * ADS_RIGHT_DS_CONTROL_ACCESS - The ObjectType GUID identifies an extended access right.
         */
        CR(0x00000100),
        /**
         * ADS_RIGHT_DS_WRITE_PROP - The ObjectType GUID identifies a property set or property of the object.
         * The ACE controls the trustee's right to write the property or property set.
         */
        WP(0x00000020);
        
        // FA(0x001F01FF),
        // FX(0x001200A0),
        // FW(0x00100116),
        // FR(0x00120089),
        // KA(0x00000019),
        // KR(0x0000003F),
        // KX(0x00000019),
        // KW(0x00000006),
        // LO(0x00000080),
        // DT(0x00000040),
        // RP(0x00000010),
        // SW(0x00000008),
        // LC(0x00000004),
        // DC(0x00000002),
        // CC(0x00000001);

        private final int value;

        /**
         * Private constructor.
         *
         * @param value int value.
         */
        private ObjectRight(int value) {
            this.value = value;
        }

        /**
         * Gest int value.
         *
         * @return int value.
         */
        public int getValue() {
            return value;
        }
    }

    /**
     * Custom/Other rights.
     */
    private long others = 0l;

    /**
     * Standard ACE rights.
     */
    private final List<AceRights.ObjectRight> rights = new ArrayList<>();

    /**
     * Default constructor.
     */
    public AceRights() {

    }

    /**
     * Parse ACE rights.
     *
     * @param value int value representing rights.
     * @return ACE rights.
     */
    public static AceRights parseValue(final int value) {
        final AceRights res = new AceRights();
        if (value == 0) {
            return res;
        }

        res.others = value;

        for (ObjectRight type : ObjectRight.values()) {
            if ((value & type.getValue()) == type.getValue()) {
                res.rights.add(type);
                res.others ^= type.getValue();
            }
        }

        return res;
    }

    /**
     * Gets custom/other rights.
     *
     * @return custom/other rights.
     */
    public long getOthers() {
        return others;
    }

    /**
     * Sets custom/other rights.
     *
     * @param others custom/other rights.
     * @return the current ACE rights.
     */
    public AceRights setOthers(final long others) {
        this.others = others;
        return this;
    }

    /**
     * Gets standard ACE rights.
     *
     * @return standard ACE rights.
     */
    public List<ObjectRight> getObjectRights() {
        return rights;
    }

    /**
     * Adds standard ACE right.
     *
     * @param right Object right.
     * @return the carrent ACE rights.
     */
    public AceRights addOjectRight(final ObjectRight right) {
        rights.add(right);
        return this;
    }

    /**
     * Gets rights as unsigned int.
     *
     * @return rights as unsigned int.
     */
    public long asUInt() {
        long res = others;

        for (ObjectRight right : rights) {
            res += right.getValue();
        }

        return res;
    }
}
