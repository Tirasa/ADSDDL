/*
 * Copyright (C) 2018 Tirasa (info@tirasa.net)
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
package net.tirasa.adsddl.ntsd.controls;

import java.nio.ByteBuffer;
import javax.naming.ldap.BasicControl;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;

/**
 * Active Directory directory synchronization (DirSync) control is an LDAP server extension that enables an application
 * to search an directory partition for objects that have changed since a previous state.
 * When you perform a DirSync search, you pass in a provider-specific data element (cookie) that identifies the
 * directory state at the time of the previous DirSync search. For the first search, you pass in a null cookie, and the
 * search returns all objects that match the filter. The search also returns a valid cookie. Store the cookie in the
 * same storage that you are synchronizing with the Active Directory server. On subsequent searches, get the cookie from
 * storage and pass it with the search request. The search results now include only the objects and attributes that have
 * changed since the previous state identified by the cookie. The search also returns a new cookie to store for the next
 * search.
 */
public class SearchOptionsControl extends BasicControl {

    private static final long serialVersionUID = -930993758829518418L;

    /**
     * LDAP_SERVER_SEARCH_OPTIONS_OID.
     * Directory synchronization control.
     */
    public static final String OID = "1.2.840.113556.1.4.1340";

    /**
     * LDAP_DIRSYNC_INCREMENTAL_VALUES | LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER | LDAP_DIRSYNC_OBJECT_SECURITY
     * LDAP_DIRSYNC_OBJECT_SECURITY: 1
     * LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER: 0x00000800
     * LDAP_DIRSYNC_PUBLIC_DATA_ONLY: 0x00002000
     * LDAP_DIRSYNC_INCREMENTAL_VALUES: 0x80000000
     */
    private final int flags = 0x80000801;

    /**
     * Constructor.
     */
    public SearchOptionsControl() {
        super(OID, true, null);
        this.value = berEncodedValue();
    }

    /**
     * BER encode the flags.
     *
     * @return flags BER encoded.
     */
    private byte[] berEncodedValue() {
        final ByteBuffer buff = ByteBuffer.allocate(8);
        buff.put((byte) 0x30); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        buff.put((byte) 0x06); // size
        buff.put((byte) 0x02); // 4bytes int tag
        buff.put((byte) 0x04); // int size
        buff.put(NumberFacility.leftTrim(NumberFacility.getBytes(flags))); // value
        return buff.array();
    }
}
