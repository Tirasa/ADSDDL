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
package net.tirasa.adsddl.ntsd.data;

import com.sun.jndi.ldap.BerEncoder;
import java.io.IOException;
import javax.naming.ldap.BasicControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SDFlagsControl extends BasicControl {

    private static final long serialVersionUID = 1L;

    private static final Logger log = LoggerFactory.getLogger(SDFlagsControl.class);

    public static final String OID = "1.2.840.113556.1.4.801";

    /**
     * OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
     */
    private final int flags;

    public SDFlagsControl() throws IOException {
        this(true, null);
    }

    public SDFlagsControl(int flags) throws IOException {
        this(true, flags);
    }

    public SDFlagsControl(boolean criticality) throws IOException {
        this(criticality, null);
    }

    public SDFlagsControl(final boolean criticality, final Integer flags) {
        super(OID, criticality, null);

        this.flags = flags == null ? 0x00000001 + 0x00000002 + 0x00000004 + 0x00000008 : flags;

        try {
            this.value = setEncodedValue();
        } catch (Exception e) {
            log.error("Error setting SD control flags", e);
            this.value = new byte[0];
        }
    }

    private byte[] setEncodedValue() throws IOException {
        final BerEncoder ber = new BerEncoder(64);
        ber.beginSeq(48); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        ber.encodeInt(flags);
        ber.endSeq();
        return ber.getTrimmedBuf();
    }
}
