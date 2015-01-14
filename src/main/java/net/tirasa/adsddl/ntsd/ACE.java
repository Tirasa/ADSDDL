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
import java.util.List;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.SignedInt;

public class ACE {

    private AceType type;

    private List<AceFlag> flags;

    private int size;

    private AceRights rights;

    private AceObjectFlags objectFlags;

    private byte[] objectType;

    private byte[] inheritedObjectType;

    private byte[] applicationData;

    private SID sid;

    ACE() {
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

        byte[] bytes = SignedInt.getBytes(buff.get(pos));
        type = AceType.parseValue(bytes[0]);
        flags = AceFlag.parseValue(bytes[1]);
        size = SignedInt.getInt(bytes[3], bytes[2]);

        pos++;
        rights = AceRights.parseValue(SignedInt.getReverseInt(buff.get(pos)));

        if (type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE || type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE) {
            pos++;
            objectFlags = AceObjectFlags.parseValue(SignedInt.getReverseInt(buff.get(pos)));

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)) {
                objectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(SignedInt.getBytes(buff.get(pos)), 0, objectType, j * 4, 4);
                }
            }

            if (objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                inheritedObjectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(SignedInt.getBytes(buff.get(pos)), 0, inheritedObjectType, j * 4, 4);
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
            System.arraycopy(SignedInt.getBytes(buff.get(pos)), 0, applicationData, index, 4);
            index += 4;
        }

        return pos;
    }

    public AceType getType() {
        return type;
    }

    public void setType(AceType type) {
        this.type = type;
    }

    public List<AceFlag> getFlags() {
        return flags;
    }

    public int getSize() {
        return size;
    }

    public byte[] getApplicationData() {
        return applicationData;
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

    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(size);

        // Add type byte
        buff.put(type.getValue());

        // add flags byte
        byte flagSRC = 0x00;
        for (AceFlag flag : flags) {
            flagSRC |= flag.getValue();
        }
        buff.put(flagSRC);

        // add size bytes (2 reversed)
        byte[] sizeSRC = SignedInt.getBytes(size);
        buff.put(sizeSRC[3]);
        buff.put(sizeSRC[2]);

        // add right mask
        buff.put(Hex.reverse(SignedInt.getBytes(rights.asInt())));

        // add object flags (from int to byte[] + reversed)
        if (objectFlags != null) {
            buff.put(Hex.reverse(SignedInt.getBytes(objectFlags.asInt())));
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
        buff.put(applicationData);

        return buff.array();
    }
}
