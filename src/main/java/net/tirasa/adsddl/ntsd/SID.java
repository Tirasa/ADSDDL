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
import java.util.List;
import java.util.Objects;
import net.tirasa.adsddl.ntsd.utils.Hex;
import net.tirasa.adsddl.ntsd.utils.SignedInt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SID {

    /**
     * Logger.
     */
    protected static final Logger log = LoggerFactory.getLogger(SID.class);

    private byte revision;

    private byte[] identifierAuthority;

    private List<byte[]> subAuthorities;

    SID() {
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
        final byte[] sidHeader = SignedInt.getBytes(buff.get(pos));

        // Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
        // This value MUST be set to 0x01.
        revision = sidHeader[0];

        //SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements 
        //in the SubAuthority array. The maximum number of elements allowed is 15.
        int subAuthorityCount = SignedInt.getInt(sidHeader[1]);
        subAuthorities = new ArrayList<>(subAuthorityCount);

        // IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the 
        // authority under which the SID was created. It describes the entity that created the SID. 
        // The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
        identifierAuthority = new byte[6];

        System.arraycopy(sidHeader, 2, identifierAuthority, 0, 2);

        pos++;
        System.arraycopy(SignedInt.getBytes(buff.get(pos)), 0, identifierAuthority, 2, 4);

        // SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely 
        // identifies a principal relative to the IdentifierAuthority. Its length is determined by 
        // SubAuthorityCount.
        for (int j = 0; j < subAuthorityCount; j++) {
            pos++;
            subAuthorities.add(Hex.reverse(SignedInt.getBytes(buff.get(pos))));
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

    public byte[] toByteArray() {
        // variable content size depending on sub authorities number
        final ByteBuffer buff = ByteBuffer.allocate(getSize());
        buff.put(revision);
        buff.put(SignedInt.getBytes(subAuthorities.size())[3]);
        buff.put(identifierAuthority);
        for (byte[] sub : subAuthorities) {
            buff.put(Hex.reverse(sub));
        }
        return buff.array();
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

        return getSubAuthorities().equals(ext.getSubAuthorities());
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 97 * hash + Arrays.hashCode(this.identifierAuthority);
        hash = 97 * hash + Objects.hashCode(this.subAuthorities);
        return hash;
    }

}
