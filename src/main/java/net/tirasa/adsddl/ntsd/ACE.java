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

import java.nio.IntBuffer;
import java.util.List;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlag;
import net.tirasa.adsddl.ntsd.data.AceRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.SignedInt;
import net.tirasa.adsddl.ntsd.utils.Unit;

public class ACE {

    private AceType type;

    private List<AceFlag> flags;

    private int size;

    private List<AceRight> rights;

    private List<AceObjectFlag> objectFlags;

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

        byte[] bytes = new Unit(buff.get(pos)).getBytes();
        type = AceType.parseValue(bytes[0]);
        flags = AceFlag.parseValue(bytes[1]);
        size = SignedInt.getInt(bytes[3], bytes[2]);

        pos++;
        rights = AceRight.parseValue(buff.get(pos));

        if (type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            pos++;
            objectFlags = AceObjectFlag.parseValue(SignedInt.getInt(Hex.reverse(new Unit(buff.get(pos)).getBytes())));

            if (objectFlags.contains(AceObjectFlag.ACE_OBJECT_TYPE_PRESENT)) {
                objectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(new Unit(buff.get(pos)).getBytes(), 0, objectType, j * 4, 4);
                }
            }

            if (objectFlags.contains(AceObjectFlag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                inheritedObjectType = new byte[16];
                for (int j = 0; j < 4; j++) {
                    pos++;
                    System.arraycopy(new Unit(buff.get(pos)).getBytes(), 0, inheritedObjectType, j * 4, 4);
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
            System.arraycopy(new Unit(buff.get(pos)).getBytes(), 0, applicationData, index, 4);
            index += 4;
        }

        return pos;
    }

    public AceType getType() {
        return type;
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

    public List<AceRight> getRights() {
        return rights;
    }

    public List<AceObjectFlag> getObjectFlags() {
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

}
