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
package net.tirasa.adsddl.ntsd;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An access control entry (ACE) is used to encode the user rights afforded to a principal, either a user or group. This
 * is generally done by combining an ACCESS_MASK and the SID of the principal.
 */
public class ACE {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(ACE.class);

    /**
     * @see AceType.
     */
    private AceType type;

    /**
     * @see AceFlag.
     */
    private List<AceFlag> flags;

    /**
     * @see AceRights.
     */
    private AceRights rights;

    /**
     * @see AceObjectFlags.
     */
    private AceObjectFlags objectFlags;

    private byte[] objectType;

    private byte[] inheritedObjectType;

    private byte[] applicationData;

    private SID sid;

    /**
     * Default constructor.
     */
    ACE() {
    }

    /**
     * Creates a new ACE instance.
     *
     * @param type ACE type.
     * @return ACE.
     */
    public static ACE newInstance(final AceType type) {
        final ACE ace = new ACE();
        ace.setType(type);
        return ace;
    }

    /**
     * Load the ACE from the buffer returning the last ACE segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    int parse(final IntBuffer buff, final int start) {
        int pos = start;

        byte[] bytes = NumberFacility.getBytes(buff.get(pos));
        type = AceType.parseValue(bytes[0]);
        flags = AceFlag.parseValue(bytes[1]);

        int size = NumberFacility.getInt(bytes[3], bytes[2]);

        pos++;
        rights = AceRights.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

        if (type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE || type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
            pos++;
            objectFlags = AceObjectFlags.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                objectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, objectType, j * 4, 4);
                }
            }

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                inheritedObjectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, inheritedObjectType, j * 4, 4);
                }
            }
        }

        pos++;
        sid = new SID();
        pos = sid.parse(buff, pos);

        int lastPos = start + (size / 4) - 1;
        applicationData = new byte[4 * (lastPos - pos)];

        int index = 0;
        while (pos < lastPos) {
            pos++;
            System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, applicationData, index, 4);
            index += 4;
        }

        return pos;
    }

    /**
     * Gets ACE type.
     *
     * @see AceType.
     * @return ACE type.
     */
    public AceType getType() {
        return type;
    }

    /**
     * Gets ACE flags.
     *
     * @see AceFlag.
     * @return ACE flags; empty list if no flag has been specified.
     */
    public List<AceFlag> getFlags() {
        return this.flags == null ? new ArrayList<AceFlag>() : this.flags;
    }

    /**
     * Optional application data. The size of the application data is determined by the AceSize field.
     *
     * @return application data; null if not available.
     */
    public byte[] getApplicationData() {
        return this.applicationData == null || this.applicationData.length == 0
                ? null
                : Arrays.copyOf(this.applicationData, this.applicationData.length);
    }

    /**
     * Sets application data.
     *
     * @param applicationData application data.
     */
    public void setApplicationData(final byte[] applicationData) {
        this.applicationData = applicationData == null || applicationData.length == 0
                ? null
                : Arrays.copyOf(applicationData, applicationData.length);
    }

    /**
     * An ACCESS_MASK that specifies the user rights allowed by this ACE.
     *
     * @see AceRights.
     * @return ACE rights.
     */
    public AceRights getRights() {
        return rights;
    }

    /**
     * A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
     * InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
     *
     * @see AceObjectFlags.
     *
     * @return Flags.
     */
    public AceObjectFlags getObjectFlags() {
        return objectFlags;
    }

    /**
     * A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object. The purpose
     * of this GUID depends on the user rights specified in the Mask field. This field is valid only if the ACE
     * _OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise, the ObjectType field is ignored. For information
     * on access rights and for a mapping of the control access rights to the corresponding GUID value that identifies
     * each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
     *
     * ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set in an ACE with any
     * ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not find an appropriate GUID, then that ACE
     * will be ignored. For more information on access checks and object access, see [MS-ADTS] section 5.1.3.3.3.
     *
     * @return ObjectType; null if not available.
     */
    public byte[] getObjectType() {
        return this.objectType == null || this.objectType.length == 0
                ? null
                : Arrays.copyOf(this.objectType, this.objectType.length);
    }

    /**
     * A GUID (16 bytes) that identifies the type of child object that can inherit the ACE. Inheritance is also
     * controlled by the inheritance flags in the ACE_HEADER, as well as by any protection against inheritance placed on
     * the child objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags
     * member. Otherwise, the InheritedObjectType field is ignored.
     *
     * @return InheritedObjectType; null if not available.
     */
    public byte[] getInheritedObjectType() {
        return this.inheritedObjectType == null || this.inheritedObjectType.length == 0
                ? null
                : Arrays.copyOf(this.inheritedObjectType, this.inheritedObjectType.length);
    }

    /**
     * The SID of a trustee. The length of the SID MUST be a multiple of 4.
     *
     * @see SID.
     * @return SID of the trustee.
     */
    public SID getSid() {
        return sid;
    }

    /**
     * An unsigned 16-bit integer that specifies the size, in bytes, of the ACE. The AceSize field can be greater than
     * the sum of the individual fields, but MUST be a multiple of 4 to ensure alignment on a DWORD boundary. In cases
     * where the AceSize field encompasses additional data for the callback ACEs types, that data is
     * implementation-specific. Otherwise, this additional data is not interpreted and MUST be ignored.
     *
     * @return ACE size.
     */
    public int getSize() {
        return 8 + (objectFlags == null ? 0 : 4)
                + (objectType == null ? 0 : 16)
                + (inheritedObjectType == null ? 0 : 16)
                + (sid == null ? 0 : sid.getSize())
                + (applicationData == null ? 0 : applicationData.length);
    }

    /**
     * Sets ACE type.
     *
     * @param type ACE type.
     * @see AceType.
     */
    public void setType(final AceType type) {
        this.type = type;
    }

    /**
     * Adds ACE flag.
     *
     * @param flag ACE flag.
     * @see AceFlag.
     */
    public void addFlag(final AceFlag flag) {
        this.flags.add(flag);
    }

    /**
     * Sets ACE rights.
     *
     * @param rights ACE rights.
     * @see AceRights.
     */
    public void setRights(final AceRights rights) {
        this.rights = rights;
    }

    /**
     * Sets object flags.
     *
     * @param objectFlags ACE object flags.
     * @see AceObjectFlags.
     */
    public void setObjectFlags(final AceObjectFlags objectFlags) {
        this.objectFlags = objectFlags;
    }

    /**
     * Sets object type, a GUID (16 bytes) that identifies a property set, property, extended right, or type of child
     * object.
     *
     * @param objectType ACE object type.
     */
    public void setObjectType(final byte[] objectType) {
        this.objectType = objectType == null || objectType.length == 0
                ? null
                : Arrays.copyOf(objectType, objectType.length);
    }

    /**
     * Sets inherited object type, a GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
     *
     * @param inheritedObjectType
     */
    public void setInheritedObjectType(final byte[] inheritedObjectType) {
        this.inheritedObjectType = inheritedObjectType == null || inheritedObjectType.length == 0
                ? null
                : Arrays.copyOf(inheritedObjectType, inheritedObjectType.length);
    }

    /**
     * Sets the SID of a trustee.
     *
     * @param sid SID of the trustee.
     * @see SID.
     */
    public void setSid(final SID sid) {
        this.sid = sid;
    }

    /**
     * Serializes to byte array.
     *
     * @return serialized ACE.
     */
    public byte[] toByteArray() {
        final int size = getSize();

        final ByteBuffer buff = ByteBuffer.allocate(size);

        // Add type byte
        buff.put(type.getValue());

        // add flags byte
        byte flagSRC = 0x00;
        for (AceFlag flag : getFlags()) {
            flagSRC |= flag.getValue();
        }
        buff.put(flagSRC);

        // add size bytes (2 reversed)
        byte[] sizeSRC = NumberFacility.getBytes(size);
        buff.put(sizeSRC[3]);
        buff.put(sizeSRC[2]);

        // add right mask
        buff.put(Hex.reverse(NumberFacility.getUIntBytes(rights.asUInt())));

        // add object flags (from int to byte[] + reversed)
        if (objectFlags != null) {
            buff.put(Hex.reverse(NumberFacility.getUIntBytes(objectFlags.asUInt())));
        }

        // add object type
        if (objectType != null) {
            buff.put(objectType);
        }

        // add inherited object type
        if (inheritedObjectType != null) {
            buff.put(inheritedObjectType);
        }

        // add sid
        buff.put(sid.toByteArray());

        // add application data
        if (applicationData != null) {
            buff.put(applicationData);
        }

        return buff.array();
    }

    /**
     * {@inheritDoc }
     *
     * @param ace ACE to be compared with.
     * @return <tt>true</tt> if equals; <tt>false</tt> otherwise.
     */
    @Override
    public boolean equals(final Object ace) {
        if (!(ace instanceof ACE)) {
            return false;
        }

        final ACE ext = ACE.class.cast(ace);

        if (getSize() != ext.getSize()) {
            log.debug("Different size");
            return false;
        }

        if (getType() != ext.getType()) {
            log.debug("Different type");
            return false;
        }

        if (!Arrays.equals(getApplicationData(), ext.getApplicationData())) {
            log.debug("Different application data");
            return false;
        }

        if (!getSid().equals(ext.getSid())) {
            log.debug("Different SID");
            return false;
        }

        if ((getObjectFlags() == null && ext.getObjectFlags() != null)
                || (getObjectFlags() != null && ext.getObjectFlags() == null)
                || (getObjectFlags() != null && ext.getObjectFlags() != null
                && getObjectFlags().asUInt() != ext.getObjectFlags().asUInt())) {
            log.debug("Different object flags");
            return false;
        }

        if ((getObjectType() != null && ext.getObjectType() == null)
                || (getObjectType() == null && ext.getObjectType() != null)
                || (getObjectType() != null && ext.getObjectType() != null
                && !Arrays.equals(getObjectType(), ext.getObjectType()))) {
            log.debug("Different object type");
            return false;
        }

        if ((getInheritedObjectType() != null && ext.getInheritedObjectType() == null)
                || (getInheritedObjectType() == null && ext.getInheritedObjectType() != null)
                || (getInheritedObjectType() != null && ext.getInheritedObjectType() != null
                && !Arrays.equals(getInheritedObjectType(), ext.getInheritedObjectType()))) {
            log.debug("Different inherited object type");
            return false;
        }

        if (getRights().asUInt() != ext.getRights().asUInt()) {
            log.debug("Different rights");
            return false;
        }

        return new HashSet<>(getFlags()).equals(new HashSet<>(ext.getFlags()));
    }

    /**
     * Serializes to string.
     *
     * @return serialized ACE.
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();
        bld.append('(');
        bld.append(type.name());
        bld.append(';');

        for (AceFlag flag : flags) {
            bld.append(flag);
        }

        bld.append(';');

        for (AceRights.ObjectRight right : rights.getObjectRights()) {
            bld.append(right.name());
        }

        if (rights.getOthers() != 0) {
            bld.append('[');
            bld.append(rights.getOthers());
            bld.append(']');
        }

        bld.append(';');

        if (objectType != null) {
            bld.append(GUID.getGuidAsString(objectType));
        }

        bld.append(';');

        if (inheritedObjectType != null) {
            bld.append(GUID.getGuidAsString(inheritedObjectType));
        }

        bld.append(';');

        bld.append(sid.toString());

        bld.append(')');

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     *
     * @return hashcode.
     */
    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.type);
        hash = 53 * hash + Objects.hashCode(this.flags);
        hash = 53 * hash + Objects.hashCode(this.rights);
        hash = 53 * hash + Objects.hashCode(this.objectFlags);
        hash = 53 * hash + Arrays.hashCode(this.objectType);
        hash = 53 * hash + Arrays.hashCode(this.inheritedObjectType);
        hash = 53 * hash + Arrays.hashCode(this.applicationData);
        hash = 53 * hash + Objects.hashCode(this.sid);
        return hash;
    }

}
