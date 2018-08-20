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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.data.AclRevision;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The access control list (ACL) packet is used to specify a list of individual access control entries (ACEs). An ACL
 * packet and an array of ACEs comprise a complete access control list.
 *
 * The individual ACEs in an ACL are numbered from 0 to n, where n+1 is the number of ACEs in the ACL. When editing an
 * ACL, an application refers to an ACE within the ACL by the ACE index.
 *
 * In the absence of implementation-specific functions to access the individual ACEs, access to each ACE MUST be
 * computed by using the AclSize and AceCount fields to parse the wire packets following the ACL to identify each
 * ACE_HEADER, which in turn contains the information needed to obtain the specific ACEs.
 *
 * There are two types of ACL:
 *
 * - A discretionary access control list (DACL) is controlled by the owner of an object or anyone granted WRITE_DAC
 * access
 * to the object. It specifies the access particular users and groups can have to an object. For example, the owner of a
 * file can use a DACL to control which users and groups can and cannot have access to the file.
 *
 * - A system access control list (SACL) is similar to the DACL, except that the SACL is used to audit rather than
 * control
 * access to an object. When an audited action occurs, the operating system records the event in the security log. Each
 * ACE in a SACL has a header that indicates whether auditing is triggered by success, failure, or both; a SID that
 * specifies a particular user or security group to monitor; and an access mask that lists the operations to audit.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc230297.aspx
 */
public class ACL {

    /**
     * Logger.
     */
    protected static final Logger LOG = LoggerFactory.getLogger(ACL.class);

    /**
     * An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported
     * for on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the
     * wire. Therefore this field MUST be set to one of the following values.
     *
     * ACL_REVISION (0x02) - When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, and 0x11 can be present in the ACL.
     * An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types.
     *
     * ACL_REVISION_DS (0x04) - When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of
     * revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for
     * DACLs.
     */
    private AclRevision revision;

    private final List<ACE> aces = new ArrayList<>();

    /**
     * Protected constructor.
     */
    ACL() {
    }

    /**
     * Load the ACL from the buffer returning the last ACL segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    int parse(final IntBuffer buff, final int start) {
        int pos = start;
        // read for Dacl
        byte[] bytes = NumberFacility.getBytes(buff.get(pos));
        revision = AclRevision.parseValue(bytes[0]);

        pos++;
        bytes = NumberFacility.getBytes(buff.get(pos));
        final int aceCount = NumberFacility.getInt(bytes[1], bytes[0]);

        for (int i = 0; i < aceCount; i++) {
            pos++;

            final ACE ace = new ACE();
            aces.add(ace);

            pos = ace.parse(buff, pos);
        }

        return pos;
    }

    /**
     * Gets ACL revision.
     *
     * @return revision.
     */
    public AclRevision getRevision() {
        return revision;
    }

    /**
     * Gets ACL size in bytes.
     *
     * @return ACL size in bytes.
     */
    public int getSize() {
        int size = 8;

        // add aces
        for (ACE ace : aces) {
            size += ace.getSize();
        }

        return size;
    }

    /**
     * Gets ACE number: an unsigned 16-bit integer that specifies the count of the number of ACE records in the ACL.
     *
     * @return ACEs' number.
     */
    public int getAceCount() {
        return aces.size();
    }

    /**
     * Gets ACL ACEs.
     *
     * @return list of ACEs.
     *
     * @see ACE.
     */
    public List<ACE> getAces() {
        return aces;
    }

    /**
     * Gets ACL ACE at the given position.
     *
     * @param i position.
     * @return ACL ACE.
     *
     * @see ACE.
     */
    public ACE getAce(final int i) {
        return aces.get(i);
    }

    /**
     * Serializes to byte array.
     *
     * @return serialized ACL.
     */
    public byte[] toByteArray() {

        int size = getSize();

        final ByteBuffer buff = ByteBuffer.allocate(size);

        // add revision
        buff.put(revision.getValue());

        // add reserved
        buff.put((byte) 0x00);

        // add size (2 bytes reversed)
        byte[] sizeSRC = NumberFacility.getBytes(size);
        buff.put(sizeSRC[3]);
        buff.put(sizeSRC[2]);

        // add ace count (2 bytes reversed)
        byte[] aceCountSRC = NumberFacility.getBytes(getAceCount());
        buff.put(aceCountSRC[3]);
        buff.put(aceCountSRC[2]);

        // add reserved (2 bytes)
        buff.put((byte) 0x00);
        buff.put((byte) 0x00);

        // add aces
        for (ACE ace : aces) {
            buff.put(ace.toByteArray());
        }

        return buff.array();
    }

    /**
     * {@inheritDoc }
     *
     * @param acl ACL to be compared with.
     * @return <tt>true</tt> if equals; <tt>false</tt> otherwise.
     */
    @Override
    public boolean equals(final Object acl) {
        if (!(acl instanceof ACL)) {
            return false;
        }

        final ACL ext = ACL.class.cast(acl);

        if (getSize() != ext.getSize()) {
            LOG.debug("Different size");
            return false;
        }

        if (getAceCount() != ext.getAceCount()) {
            LOG.debug("Different ace count");
            return false;
        }

        for (int i = 0; i < aces.size(); i++) {
            if (!getAce(i).equals(ext.getAce(i))) {
                LOG.debug("Different ace: {}-{}", getAce(i), ext.getAce(i));
                return false;
            }
        }

        return true;
    }

    /**
     * Serializes to string.
     *
     * @return serialized ACL.
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();
        bld.append('P');

        for (ACE ace : aces) {
            bld.append(ace.toString());
        }

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     *
     * @return hashcode.
     */
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 43 * hash + Objects.hashCode(this.aces);
        return hash;
    }

}
