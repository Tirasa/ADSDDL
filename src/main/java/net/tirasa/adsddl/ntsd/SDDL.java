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
package net.tirasa.adsddl.ntsd;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.util.Arrays;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The SECURITY_DESCRIPTOR structure defines the security attributes of an object. These attributes specify who owns the
 * object; who can access the object and what they can do with it; what level of audit logging should be applied to the
 * object; and what kind of restrictions apply to the use of the security descriptor.
 *
 * Security descriptors appear in one of two forms, absolute or self-relative.
 *
 * A security descriptor is said to be in absolute format if it stores all of its security information via pointer
 * fields, as specified in the RPC representation in section 2.4.6.1.
 *
 * A security descriptor is said to be in self-relative format if it stores all of its security information in a
 * contiguous block of memory and expresses all of its pointer fields as offsets from its beginning. The order of
 * appearance of pointer target fields is not required to be in any particular order; locating the OwnerSid, GroupSid,
 * Sacl, and/or Dacl should only be based on OffsetOwner, OffsetGroup, OffsetSacl, and/or OffsetDacl pointers found in
 * the fixed portion of the relative security descriptor.<br>
 *
 * The self-relative form of the security descriptor is required if one wants to transmit the SECURITY_DESCRIPTOR
 * structure as an opaque data structure for transmission in communication protocols over a wire, or for storage on
 * secondary media; the absolute form cannot be transmitted because it contains pointers to objects that are generally
 * not accessible to the recipient.
 *
 * When a self-relative security descriptor is transmitted over a wire, it is sent in little-endian format and requires
 * no padding.
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc230366.aspx" target="_top">cc230366</a>
 */
public class SDDL {

    /**
     * Logger.
     */
    protected static final Logger LOG = LoggerFactory.getLogger(SDDL.class);

    /**
     * An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure.
     * This field MUST be set to one.
     */
    private byte revision;

    /**
     * An unsigned 16-bit field that specifies control access bit flags. The Self Relative (SR) bit MUST be set when the
     * security descriptor is in self-relative format.
     */
    private byte[] controlFlags;

    /**
     * An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the owner of the object to
     * which the security descriptor is associated. This must be a valid offset if the OD flag is not set. If this field
     * is set to zero, the OwnerSid field MUST not be present.
     */
    private long offsetOwner;

    /**
     * An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the group of the object to
     * which the security descriptor is associated. This must be a valid offset if the GD flag is not set. If this field
     * is set to zero, the GroupSid field MUST not be present.
     */
    private long offsetGroup;

    /**
     * An unsigned 32-bit integer that specifies the offset to the ACL that contains system ACEs. Typically, the system
     * ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, or
     * SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE. This must be a valid offset if the SP flag is set;
     * if the SP flag is not set, this field MUST be set to zero. If this field is set to zero, the Sacl field MUST not
     * be present.
     */
    private long offsetSACL;

    /**
     * An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs that control access.
     * Typically, the DACL contains ACEs that grant or deny access to principals or groups. This must be a valid offset
     * if the DP flag is set; if the DP flag is not set, this field MUST be set to zero. If this field is set to zero,
     * the Dacl field MUST not be present.
     */
    private long offsetDACL;

    /**
     * The SID of the owner of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
     * the OffsetOwner field is not zero.
     */
    private SID owner;

    /**
     * The SID of the group of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
     * the GroupOwner field is not zero.
     */
    private SID group;

    /**
     * The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the SP flag
     * is set.
     */
    private ACL dacl;

    /**
     * The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the DP flag
     * is set.
     */
    private ACL sacl;

    /**
     * Constructor.
     *
     * @param src source as byte array.
     */
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
        final byte[] header = NumberFacility.getBytes(buff.get(pos));
        revision = header[0];

        /**
         * Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative
         * (SR) bit MUST be set when the security descriptor is in self-relative format.
         */
        controlFlags = new byte[] { header[3], header[2] };
        final boolean[] controlFlag = NumberFacility.getBits(controlFlags);

        pos++;
        /**
         * OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
         * specifies the owner of the object to which the security descriptor is associated. This must be a valid
         * offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
         */
        if (!controlFlag[15]) {
            offsetOwner = NumberFacility.getReverseUInt(buff.get(pos));
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
            offsetGroup = NumberFacility.getReverseUInt(buff.get(pos));
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
            offsetSACL = NumberFacility.getReverseUInt(buff.get(pos));
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
            offsetDACL = NumberFacility.getReverseUInt(buff.get(pos));
        } else {
            offsetDACL = 0;
        }

        /**
         * OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the OffsetOwner field is not zero.
         */
        if (offsetOwner > 0) {
            // read for OwnerSid
            pos = (int) (offsetOwner / 4);
            owner = new SID();
            pos = owner.parse(buff, pos);
        }

        /**
         * GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4.
         * This field MUST be present if the GroupOwner field is not zero.
         */
        if (offsetGroup > 0) {
            // read for GroupSid
            pos = (int) (offsetGroup / 4);
            group = new SID();
            pos = group.parse(buff, pos);
        }

        /**
         * Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the SP flag is set.
         */
        if (offsetSACL > 0) {
            // read for Sacl
            pos = (int) (offsetSACL / 4);
            sacl = new ACL();
            pos = sacl.parse(buff, pos);
        }

        /**
         * Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
         * be present if the DP flag is set.
         */
        if (offsetDACL > 0) {
            pos = (int) (offsetDACL / 4);
            dacl = new ACL();
            pos = dacl.parse(buff, pos);
        }

        return pos;
    }

    /**
     * Gets size in terms of number of bytes.
     *
     * @return size.
     */
    public int getSize() {
        return 20 + (sacl == null ? 0 : sacl.getSize())
                + (dacl == null ? 0 : dacl.getSize())
                + (owner == null ? 0 : owner.getSize())
                + (group == null ? 0 : group.getSize());
    }

    /**
     * Get revison.
     *
     * @return An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure..
     */
    public byte getRevision() {
        return revision;
    }

    /**
     * Gets control.
     *
     * @return An unsigned 16-bit field that specifies control access bit flags.
     */
    public byte[] getControlFlags() {
        return controlFlags;
    }

    /**
     * Gets owner.
     *
     * @return The SID of the owner of the object.
     */
    public SID getOwner() {
        return owner;
    }

    /**
     * Gets group.
     *
     * @return The SID of the group of the object.
     */
    public SID getGroup() {
        return group;
    }

    /**
     * Gets DACL.
     *
     * @return The DACL of the object.
     */
    public ACL getDacl() {
        return dacl;
    }

    /**
     * Gets SACL.
     *
     * @return The SACL of the object.
     */
    public ACL getSacl() {
        return sacl;
    }

    /**
     * Serializes SDDL as byte array.
     *
     * @return SDL as byte array.
     */
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
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(owner.toByteArray());
            nextAvailablePosition += owner.getSize();
        }

        // add offset group
        buff.position(8);

        // add group SID
        if (group == null) {
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(group.toByteArray());
            nextAvailablePosition += group.getSize();
        }

        // add offset sacl
        buff.position(12);

        // add SACL
        if (sacl == null) {
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(sacl.toByteArray());
            nextAvailablePosition += sacl.getSize();
        }

        // add offset dacl
        buff.position(16);

        // add DACL
        if (dacl == null) {
            buff.putInt(0);
        } else {
            buff.put(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
            buff.position(nextAvailablePosition);
            buff.put(dacl.toByteArray());
        }

        return buff.array();
    }

    /**
     * {@inheritDoc }
     */
    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof SDDL)) {
            return false;
        }

        final SDDL ext = SDDL.class.cast(o);

        if (getSize() != ext.getSize()) {
            LOG.debug("Different size");
            return false;
        }

        if (!Arrays.equals(getControlFlags(), ext.getControlFlags())) {
            LOG.debug("Different control flags");
            return false;
        }

        if (!getOwner().equals(ext.getOwner())) {
            LOG.debug("Different owner ....\nEspected; {}\nActual: {}",
                    getOwner().toString(), ext.getOwner().toString());
            return false;
        }

        if (!getGroup().equals(ext.getGroup())) {
            LOG.debug("Different group ....\nEspected; {}\nActual: {}",
                    getGroup().toString(), ext.getGroup().toString());
            return false;
        }

        if (!getDacl().equals(ext.getDacl())) {
            LOG.debug("Different dacl");
            return false;
        }

        if (!getSacl().equals(ext.getSacl())) {
            LOG.debug("Different sacl");
            return false;
        }
        return true;
    }

    /**
     * Serializes SDDL as string.
     *
     * @return SDDL string representation.
     *
     * @see <a href="https://msdn.microsoft.com/en-us/library/hh877835.aspx" target="_top">hh877835</a>
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();

        if (owner != null) {
            bld.append("O:");
            bld.append(owner.toString());
        }
        if (group != null) {
            bld.append("G:");
            bld.append(group.toString());
        }

        if (dacl != null) {
            bld.append("D:");
            bld.append(dacl.toString());
        }

        if (sacl != null) {
            bld.append("S:");
            bld.append(sacl.toString());
        }

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     */
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
