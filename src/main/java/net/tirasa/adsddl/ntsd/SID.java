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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A security identifier (SID) uniquely identifies a security principal. Each security principal has a unique SID that
 * is issued by a security agent. The agent can be a Windows local system or domain. The agent generates the SID when
 * the security principal is created. The SID can be represented as a character string or as a structure. When
 * represented as strings, for example in documentation or logs, SIDs are expressed as follows:
 *
 * S-1-IdentifierAuthority-SubAuthority1-SubAuthority2-...-SubAuthorityn
 *
 * The top-level issuer is the authority. Each issuer specifies, in an implementation-specific manner, how many integers
 * identify the next issuer.
 *
 * A newly created account store is assigned a 96-bit identifier (a cryptographic strength (pseudo) random number).
 *
 * A newly created security principal in an account store is assigned a 32-bit identifier that is unique within the
 * store.
 *
 * The last item in the series of SubAuthority values is known as the relative identifier (RID). Differences in the RID
 * are what distinguish the different SIDs generated within a domain.
 *
 * Consumers of SIDs SHOULD NOT rely on anything more than that the SID has the appropriate structure.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc230371.aspx
 * @see https://msdn.microsoft.com/en-us/library/gg465313.aspx
 */
public class SID {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(SID.class);

    /**
     * An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
     */
    private byte revision;

    /**
     * A SID_IDENTIFIER_AUTHORITY (6 bytes) structure that indicates the authority under which the SID was created.
     * It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created
     * by the NT SID authority.
     */
    private byte[] identifierAuthority;

    /**
     * A variable length list of unsigned 32-bit integers that uniquely identifies a principal relative to the
     * IdentifierAuthority.
     */
    private final List<byte[]> subAuthorities;

    SID() {
        subAuthorities = new ArrayList<>();
    }

    /**
     * Instances a new SID with the given identifier authority.
     *
     * @param identifier identifier authority.
     * @return the SID instance.
     */
    public static SID newInstance(final byte[] identifier) {
        final SID sid = new SID();
        sid.setRevision((byte) 0x01);
        sid.setIdentifierAuthority(identifier);
        return sid;
    }

    /**
     * Instances a SID instance of the given byte array.
     *
     * @param src SID as byte array.
     * @return SID instance.
     */
    public static SID parse(final byte[] src) {
        final ByteBuffer sddlBuffer = ByteBuffer.wrap(src);
        final SID sid = new SID();
        sid.parse(sddlBuffer.asIntBuffer(), 0);
        return sid;
    }

    /**
     * Load the SID from the buffer returning the last SID segment position into the buffer.
     *
     * @param buff source buffer.
     * @param start start loading position.
     * @return last loading position.
     */
    int parse(final IntBuffer buff, final int start) {
        int pos = start;

        // Check for a SID (http://msdn.microsoft.com/en-us/library/cc230371.aspx)
        final byte[] sidHeader = NumberFacility.getBytes(buff.get(pos));

        // Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
        // This value MUST be set to 0x01.
        revision = sidHeader[0];

        //SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements 
        //in the SubAuthority array. The maximum number of elements allowed is 15.
        int subAuthorityCount = NumberFacility.getInt(sidHeader[1]);

        // IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the 
        // authority under which the SID was created. It describes the entity that created the SID. 
        // The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
        identifierAuthority = new byte[6];

        System.arraycopy(sidHeader, 2, identifierAuthority, 0, 2);

        pos++;
        System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, identifierAuthority, 2, 4);

        // SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely 
        // identifies a principal relative to the IdentifierAuthority. Its length is determined by 
        // SubAuthorityCount.
        for (int j = 0; j < subAuthorityCount; j++) {
            pos++;
            subAuthorities.add(Hex.reverse(NumberFacility.getBytes(buff.get(pos))));
        }

        return pos;
    }

    /**
     * Gets revision level of the SID.
     *
     * @return revision.
     */
    public byte getRevision() {
        return revision;
    }

    /**
     * Gets sub-authority number: an 8-bit unsigned integer that specifies the number of elements in the SubAuthority
     * array. The maximum number of elements allowed is 15.
     *
     * @return sub-authorities number.
     */
    public int getSubAuthorityCount() {
        return subAuthorities == null ? 0 : subAuthorities.size() > 15 ? 15 : subAuthorities.size();
    }

    /**
     * Gets identifier authority: 6 bytes describing the entity that created the SID.
     *
     * @return identifier authority.
     */
    public byte[] getIdentifierAuthority() {
        return identifierAuthority == null ? null : Arrays.copyOf(identifierAuthority, identifierAuthority.length);
    }

    /**
     * Gets sub-authorities: a list of unsigned 32-bit integers that uniquely identifies a principal
     * relative to the IdentifierAuthority.
     *
     * @return sub-authorities.
     */
    public List<byte[]> getSubAuthorities() {
        final List<byte[]> res = new ArrayList<>(getSubAuthorityCount());
        for (byte[] sub : subAuthorities) {
            if (sub != null) {
                res.add(Arrays.copyOf(sub, sub.length));
            }
        }
        return Collections.unmodifiableList(res);
    }

    /**
     * Gets size of the SID byte array form.
     *
     * @return size of SID byte aray form.
     */
    public int getSize() {
        return 8 + subAuthorities.size() * 4;
    }

    /**
     * Sets revision level of the SID.
     *
     * @param revision revision.
     * @return the current SID instance.
     */
    public SID setRevision(byte revision) {
        this.revision = revision;
        return this;
    }

    /**
     * Sets idetifier authority: 6 bytes describing the entity that created the SID.
     *
     * @param identifierAuthority identifier authority.
     * @return the current SID instance.
     */
    public SID setIdentifierAuthority(byte[] identifierAuthority) {
        if (identifierAuthority == null || identifierAuthority.length != 6) {
            throw new IllegalArgumentException("Invalid identifier authority");
        }

        this.identifierAuthority = Arrays.copyOf(identifierAuthority, identifierAuthority.length);
        return this;
    }

    /**
     * Adds sub-authority:a principal relative to the IdentifierAuthority.
     *
     * @param sub sub-authority.
     * @return the current SID instance.
     */
    public SID addSubAuthority(byte[] sub) {
        if (sub == null || sub.length != 4) {
            throw new IllegalArgumentException("Invalid sub-authority to be added");
        }

        this.subAuthorities.add(Arrays.copyOf(sub, sub.length));
        return this;
    }

    /**
     * Serializes to byte array.
     *
     * @return serialized SID.
     */
    public byte[] toByteArray() {
        // variable content size depending on sub authorities number
        final ByteBuffer buff = ByteBuffer.allocate(getSize());
        buff.put(revision);
        buff.put(NumberFacility.getBytes(subAuthorities.size())[3]);
        buff.put(identifierAuthority);
        for (byte[] sub : subAuthorities) {
            buff.put(Hex.reverse(sub));
        }
        return buff.array();
    }

    /**
     * Serializes to string.
     *
     * @return serialized SID.
     */
    @Override
    public String toString() {
        final StringBuilder bld = new StringBuilder();
        bld.append("S-1-");

        if (identifierAuthority[0] == 0x00 && identifierAuthority[1] == 0x00) {
            bld.append(NumberFacility.getUInt(
                    identifierAuthority[2], identifierAuthority[3], identifierAuthority[4], identifierAuthority[5]));
        } else {
            bld.append(Hex.get(identifierAuthority));
        }

        if (subAuthorities.isEmpty()) {
            bld.append("-0");
        } else {
            for (byte[] sub : subAuthorities) {
                bld.append("-");
                bld.append(NumberFacility.getUInt(sub));
            }
        }

        return bld.toString();
    }

    /**
     * {@inheritDoc }
     *
     * @param sid SID to be compared with.
     * @return <tt>true</tt> if equals; <tt>false</tt> otherwise.
     */
    @Override
    public boolean equals(final Object sid) {
        if (!(sid instanceof SID)) {
            return false;
        }

        final SID ext = SID.class.cast(sid);

        if (getSize() != ext.getSize()) {
            log.debug("Different size");
            return false;
        }

        if (getSubAuthorityCount() != ext.getSubAuthorityCount()) {
            log.debug("Different sub authorities");
            return false;
        }

        if (!Arrays.equals(getIdentifierAuthority(), ext.getIdentifierAuthority())) {
            log.debug("Different identifier authority: {}-{}",
                    Hex.get(identifierAuthority), Hex.get(ext.getIdentifierAuthority()));
            return false;
        }

        for (int i = 0; i < subAuthorities.size(); i++) {
            if (!Arrays.equals(subAuthorities.get(i), ext.getSubAuthorities().get(i))) {
                log.debug("Different sub authority: {}-{}",
                        Hex.get(subAuthorities.get(i)), Hex.get(ext.getSubAuthorities().get(i)));
                return false;
            }
        }

        return true;
    }

    /**
     * {@inheritDoc }
     *
     * @return hashcode.
     */
    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + Arrays.hashCode(this.identifierAuthority);
        hash = 97 * hash + Objects.hashCode(this.subAuthorities);
        return hash;
    }

}
