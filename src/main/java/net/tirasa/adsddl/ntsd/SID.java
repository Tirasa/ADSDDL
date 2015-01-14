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
import java.util.List;
import net.tirasa.adsddl.ntsd.utils.SignedInt;

public class SID {

    private byte revision;

    private int subAuthorityCount;

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
        subAuthorityCount = SignedInt.getInt(sidHeader[1]);
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
            subAuthorities.add(SignedInt.getBytes(buff.get(pos)));
        }

        return pos;
    }

    public byte getRevision() {
        return revision;
    }

    public int getSubAuthorityCount() {
        return subAuthorityCount;
    }

    public byte[] getIdentifierAuthority() {
        return identifierAuthority;
    }

    public List<byte[]> getSubAuthorities() {
        return subAuthorities;
    }

    public byte[] toByteArray() {
        final ByteBuffer buff = ByteBuffer.allocate(8 + subAuthorityCount * 4);
        buff.put(revision);
        buff.put(SignedInt.getBytes(subAuthorityCount)[3]);
        buff.put(identifierAuthority);
        for (byte[] sub : subAuthorities) {
            buff.put(sub);
        }
        return buff.array();
    }
}
