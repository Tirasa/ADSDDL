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
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SID {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(SID.class);

    private byte revision;

    private byte[] identifierAuthority;

    private final List<byte[]> subAuthorities;

    SID() {
        subAuthorities = new ArrayList<>();
    }

    public static SID newInstance(final byte[] identifier) {
        final SID sid = new SID();
        sid.setRevision((byte) 0x01);
        sid.setIdentifierAuthority(identifier);
        return sid;
    }

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

    public byte getRevision() {
        return revision;
    }

    public int getSubAuthorityCount() {
        return subAuthorities.size();
    }

    public byte[] getIdentifierAuthority() {
        return identifierAuthority;
    }

    public List<byte[]> getSubAuthorities() {
        return subAuthorities;
    }

    public int getSize() {
        return 8 + subAuthorities.size() * 4;
    }

    void setRevision(byte revision) {
        this.revision = revision;
    }

    public SID setIdentifierAuthority(byte[] identifierAuthority) {
        final ByteBuffer buff = ByteBuffer.allocate(6);

        if (identifierAuthority != null) {
            buff.position(6 - identifierAuthority.length);
            buff.put(identifierAuthority);
        }

        this.identifierAuthority = buff.array();
        return this;
    }

    public SID addSubAuthority(byte[] sub) {
        if (sub != null) {
            this.subAuthorities.add(sub);
        }
        return this;
    }

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

    @Override
    public boolean equals(final Object o) {
        if (!(o instanceof SID)) {
            return false;
        }

        final SID ext = SID.class.cast(o);

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

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + Arrays.hashCode(this.identifierAuthority);
        hash = 97 * hash + Objects.hashCode(this.subAuthorities);
        return hash;
    }

}
