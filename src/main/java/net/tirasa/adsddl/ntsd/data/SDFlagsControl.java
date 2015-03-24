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
package net.tirasa.adsddl.ntsd.data;

import com.sun.jndi.ldap.BerEncoder;
import java.io.IOException;
import javax.naming.ldap.BasicControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 *
 * When performing an LDAP operation (modify or search), the client may supply an SD Flags Control
 * LDAP_SERVER_SD_FLAGS_OID (1.2.840.113556.1.4.801) with the operation. The value of the control is an integer, which
 * is used to identify which security descriptor (SD) parts the client intends to read or modify. When the control is
 * not specified, then the default value of 15 (0x0000000F) is used.
 *
 * The SD parts are identified using the following bit values: OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
 * DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, which correspond to OWNER, GROUP, DACL and SACL SD fields,
 * respectively.
 *
 * If the LDAP_SERVER_SD_FLAGS_OID control is present in an LDAP search request, the server returns an SD with the parts
 * specified in the control when the SD attribute name is explicitly mentioned in the requested attribute list, or when
 * the requested attribute list is empty, or when all attributes are requested ([RFC2251] section 4.5.1). Without the
 * presence of this control, the server returns an SD only when the SD attribute name is explicitly mentioned in the
 * requested attribute list.
 *
 * For update operations, the bits identify which SD parts are affected by the operation. Note that the client may
 * supply values for other (or all) SD fields. However, the server only updates the fields that are identified by the SD
 * control. The remaining fields are ignored. When performing an LDAP add operation, the client can supply an SD flags
 * control with the operation; however, it will be ignored by the server.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223733.aspx
 */
public class SDFlagsControl extends BasicControl {

    private static final long serialVersionUID = 1L;

    /**
     * Logger.
     */
    private static final Logger log = LoggerFactory.getLogger(SDFlagsControl.class);

    /**
     * LDAP_SERVER_SD_FLAGS_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.801";

    /**
     * SD Flags Control:
     * OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION.
     */
    private final int flags;

    /**
     * Constructor.
     */
    public SDFlagsControl() {
        this(true, null);
    }

    /**
     * Constructor.
     *
     * @param flags SD Flags Control.
     */
    public SDFlagsControl(int flags) {
        this(true, flags);
    }

    /**
     * Constructor.
     *
     * @param criticality The control's criticality.
     */
    public SDFlagsControl(boolean criticality) {
        this(criticality, null);
    }

    /**
     * Constructor.
     *
     * @param criticality The control's criticality.
     * @param flags SD Flags Control.
     */
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
