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
import java.util.ArrayList;
import java.util.List;
import net.tirasa.adsddl.ntsd.data.AclRevision;
import net.tirasa.adsddl.ntsd.utils.SignedInt;
import net.tirasa.adsddl.ntsd.utils.Unit;

public class ACL {

    private AclRevision revision;

    private byte[] size;

    private byte[] aceCount;

    private final List<ACE> aces = new ArrayList<>();

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
        byte[] bytes = new Unit(buff.get(pos)).getBytes();
        revision = AclRevision.parseValue(bytes[0]);
        size = new byte[] { bytes[3], bytes[2] };

        pos++;
        bytes = new Unit(buff.get(pos)).getBytes();
        aceCount = new byte[] { bytes[1], bytes[0] };

        for (int i = 0; i < SignedInt.getInt(aceCount); i++) {
            pos++;

            final ACE ace = new ACE();
            aces.add(ace);

            pos = ace.parse(buff, pos);
        }

        return pos;
    }

    public AclRevision getRevision() {
        return revision;
    }

    public byte[] getSize() {
        return size;
    }

    public byte[] getAceCount() {
        return aceCount;
    }

    public List<ACE> getAces() {
        return aces;
    }

    public ACE getAce(final int i) {
        return aces.get(i);
    }
}
