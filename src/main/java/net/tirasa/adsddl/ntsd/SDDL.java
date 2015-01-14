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
import java.util.Arrays;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.SignedInt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SDDL {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(SDDL.class);

    private byte revision;

    private byte[] controlFlags;

    private int offsetOwner;

    private int offsetGroup;

    private int offsetSACL;

    private int offsetDACL;

    private SID owner;

    private SID group;

    private ACL dacl;

    private ACL sacl;

    public SDDL(byte[] src) {
        final ByteBuffer sddlBuffer = ByteBuffer.wrap(src);
        parse(sddlBuffer.asIntBuffer(), 0);
    }

    /**
     * Load the SDDL from the buffer returning the last SDDL segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    private int parse(final IntBuffer buff, final int start) {
        int pos = start;

        /**
         * Revision (1 byte): An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR
         * structure. This field MUST be set to one.
         */
        final byte[] header = SignedInt.getBytes(buff.get(pos));
        revision = header[0];

        /**
         * Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative
         * (SR) bit MUST be set when the security descriptor is in self-relative format.
         */
        controlFlags = new byte[] { header[3], header[2] };
        final boolean[] controlFlag = SignedInt.getBits(controlFlags);

        pos++;
        /**
         * OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
         * specifies the owner of the object to which the security descriptor is associated. This must be a valid
         * offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
         */
        if (!controlFlag[15]) {
            offsetOwner = SignedInt.getReverseInt(buff.get(pos));
        } else {
            offsetOwner = 0;
        }

        pos++;

        /**
         * OffsetGroup (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
         * specifies the group of the object to which the security descriptor is associated. This must be a valid
         * offset if the GD flag is not set. If this field is set to zero, the GroupSid field MUST not be present.
         */
        if (!controlFlag[14]) {
            offsetGroup = SignedInt.getReverseInt(buff.get(pos));
        } else {
            offsetGroup = 0;
        }

        pos++;

        /**
         * OffsetSacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains
         * system ACEs. Typically, the system ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE,
         * SYSTEM_AUDIT_CALLBACK_ACE, or SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE (as specified
         * in section 2.4.4.13). This must be a valid offset if the SP flag is set; if the SP flag is not set, this
         * field MUST be set to zero. If this field is set to zero, the Sacl field MUST not be present.
         */
        if (controlFlag[11]) {
            offsetSACL = SignedInt.getReverseInt(buff.get(pos));
        } else {
            offsetSACL = 0;
        }

        pos++;

        /**
         * OffsetDacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs
         * that control access. Typically, the DACL contains ACEs that grant or deny access to principals or groups.
         * This must be a valid offset if the DP flag is set; if the DP flag is not set, this field MUST be set to
         * zero. If this field is set to zero, the Dacl field MUST not be present.
         */
        if (controlFlag[13]) {
            offsetDACL = SignedInt.getReverseInt(buff.get(pos));
        } else {
            offsetDACL = 0;
        }

        /**
         * OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the OffsetOwner field is not zero.
         */
        if (offsetOwner > 0) {
            pos = offsetOwner / 4;
            // read for OwnerSid
            owner = new SID();
            pos = owner.parse(buff, pos);
        }

        /**
         * GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the GroupOwner field is not zero.
         */
        if (offsetGroup > 0) {
            // read for GroupSid
            pos = offsetGroup / 4;
            group = new SID();
            pos = group.parse(buff, pos);
        }

        /**
         * Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the SP flag is set.
         */
        if (offsetSACL > 0) {
            // read for Sacl
            pos = offsetSACL / 4;
            sacl = new ACL();
            pos = sacl.parse(buff, pos);
        }

        /**
         * Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the DP flag is set.
         */
        if (offsetDACL > 0) {
            pos = offsetDACL / 4;
            dacl = new ACL();
            pos = dacl.parse(buff, pos);
        }

        return pos;
    }

    public int getSize() {
        return 20 + (sacl == null ? 0 : sacl.getSize())
                + (dacl == null ? 0 : dacl.getSize())
                + (owner == null ? 0 : owner.getSize())
                + (group == null ? 0 : group.getSize());
    }

    public byte getRevision() {
        return revision;
    }

    public byte[] getControlFlags() {
        return controlFlags;
    }

    public SID getOwner() {
        return owner;
    }

    public SID getGroup() {
        return group;
    }

    public ACL getDacl() {
        return dacl;
    }

    public ACL getSacl() {
        return sacl;
    }

    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(getSize());

        // add revision
        buff.put(revision);

        // add reserved
        buff.put((byte) 0x00);

        // add contro flags
        buff.put(controlFlags[1]);
        buff.put(controlFlags[0]);

        // add offset owner
        buff.position(4);

        int nextAvailablePosition = 20;
        // add owner SID
        if (owner == null) {
            buff.put(SignedInt.getBytes(0));
        } else {
            buff.put(Hex.reverse(SignedInt.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(owner.toByteArray());
            nextAvailablePosition += 4;
        }

        // add offset group
        buff.position(8);

        // add group SID
        if (group == null) {
            buff.put(SignedInt.getBytes(0));
        } else {
            buff.put(Hex.reverse(SignedInt.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(group.toByteArray());
            nextAvailablePosition += 4;
        }

        // add offset sacl
        buff.position(12);

        // add SACL
        if (sacl == null) {
            buff.put(SignedInt.getBytes(0));
        } else {
            buff.put(Hex.reverse(SignedInt.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sacl.toByteArray());
            nextAvailablePosition += sacl.getSize();
        }

        // add offset dacl
        buff.position(16);

        // add DACL
        if (dacl == null) {
            buff.put(SignedInt.getBytes(0));
        } else {
            buff.put(Hex.reverse(SignedInt.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(dacl.toByteArray());
        }

        return buff.array();
    }

    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof SDDL)) {
            return false;
        }

        final SDDL ext = SDDL.class.cast(o);

        if (getSize() != ext.getSize()) {
            log.debug("Different size");
            return false;
        }

        if (!Arrays.equals(getControlFlags(), ext.getControlFlags())) {
            log.debug("Different control flags");
            return false;
        }

        if (!getOwner().equals(ext.getOwner())) {
            log.debug("Different owner");
            return false;
        }

        if (!getGroup().equals(ext.getGroup())) {
            log.debug("Different group");
            return false;
        }

        if (!getDacl().equals(ext.getDacl())) {
            log.debug("Different dacl");
            return false;
        }

        if (!getSacl().equals(ext.getSacl())) {
            log.debug("Different sacl");
            return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 71 * hash + Arrays.hashCode(this.controlFlags);
        hash = 71 * hash + Objects.hashCode(this.owner);
        hash = 71 * hash + Objects.hashCode(this.group);
        hash = 71 * hash + Objects.hashCode(this.dacl);
        hash = 71 * hash + Objects.hashCode(this.sacl);
        return hash;
    }
}
