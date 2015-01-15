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

public class ACE {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(ACE.class);

    private AceType type;

    private List<AceFlag> flags;

    private AceRights rights;

    private AceObjectFlags objectFlags;

    private byte[] objectType;

    private byte[] inheritedObjectType;

    private byte[] applicationData;

    private SID sid;

    ACE() {
    }

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

    public AceType getType() {
        return type;
    }

    public List<AceFlag> getFlags() {
        return this.flags == null ? new ArrayList<AceFlag>() : this.flags;
    }

    public byte[] getApplicationData() {
        return this.applicationData == null ? new byte[0] : this.applicationData;
    }

    public AceRights getRights() {
        return rights;
    }

    public AceObjectFlags getObjectFlags() {
        return objectFlags;
    }

    public byte[] getObjectType() {
        return objectType;
    }

    public byte[] getInheritedObjectType() {
        return inheritedObjectType;
    }

    public SID getSid() {
        return sid;
    }

    public int getSize() {
        return 8 + (objectFlags == null ? 0 : 4)
                + (objectType == null ? 0 : 16)
                + (inheritedObjectType == null ? 0 : 16)
                + (sid == null ? 0 : sid.getSize())
                + (applicationData == null ? 0 : applicationData.length);
    }

    public void setType(final AceType type) {
        this.type = type;
    }

    public void addFlag(final AceFlag flag) {
        this.flags.add(flag);
    }

    public void setRights(final AceRights rights) {
        this.rights = rights;
    }

    public void setObjectFlags(final AceObjectFlags objectFlags) {
        this.objectFlags = objectFlags;
    }

    public void setObjectType(final byte[] objectType) {
        this.objectType = objectType;
    }

    public void setInheritedObjectType(final byte[] inheritedObjectType) {
        this.inheritedObjectType = inheritedObjectType;
    }

    public void setSid(final SID sid) {
        this.sid = sid;
    }

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

    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof ACE)) {
            return false;
        }

        final ACE ext = ACE.class.cast(o);

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
