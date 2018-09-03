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
public class DirSyncControl extends BasicControl {

    private static final long serialVersionUID = -930993758829518418L;

    /**
     * LDAP_SERVER_DIRSYNC_OID.
     * Directory synchronization control.
     */
    public static final String OID = "1.2.840.113556.1.4.841";

    /**
     * Empty cookie.
     */
    private static final byte[] EMPTY_COOKIE = new byte[0];

    /**
     * LDAP_DIRSYNC_INCREMENTAL_VALUES | LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER | LDAP_DIRSYNC_OBJECT_SECURITY
     * LDAP_DIRSYNC_OBJECT_SECURITY: 0x00000001
     * LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER: 0x00000800
     * LDAP_DIRSYNC_PUBLIC_DATA_ONLY: 0x00002000
     * LDAP_DIRSYNC_INCREMENTAL_VALUES: 0x80000000
     */
    private int flags = 0x80000801;

    private final byte[] cookie;

    /**
     * Constructor.
     * Specify an empty cookie.
     */
    public DirSyncControl() {
        super(OID, true, null);
        this.cookie = EMPTY_COOKIE;
        super.value = berEncodedValue();
    }

    /**
     * Constructor.
     *
     * @param cookie cookie.
     */
    public DirSyncControl(byte[] cookie) {
        super(OID, true, cookie);
        this.cookie = cookie;
        super.value = berEncodedValue();
    }

    /**
     * BER encode the cookie value.
     *
     * @param cookie cookie value to be encoded.
     * @return ber encoded cookie value.
     */
    private byte[] berEncodedValue() {
        final byte[] cookieSize = NumberFacility.leftTrim(NumberFacility.getBytes(cookie.length));
        final byte[] size = NumberFacility.leftTrim(NumberFacility.getBytes(14 + cookieSize.length + cookie.length));

        final ByteBuffer buff = ByteBuffer.allocate(1 + 1 + size.length + 14 + cookieSize.length + cookie.length);

        buff.put((byte) 0x30); // (Ber.ASN_SEQUENCE | Ber.ASN_CONSTRUCTOR);
        buff.put((byte) (size.length == 1 ? 0x81 : size.length == 2 ? 0x82 : 0x83)); // size type (short or long form)
        buff.put(size); // sequence size
        buff.put((byte) 0x02); // 4bytes int tag
        buff.put((byte) 0x04); // int size
        buff.putInt(flags); // flags
        buff.put((byte) 0x02); // 4bytes int tag
        buff.put((byte) 0x04); // int size
        buff.putInt(Integer.MAX_VALUE); // max attribute count
        buff.put((byte) 0x04); // byte array tag
        buff.put((byte) (cookieSize.length == 1 ? 0x81 : cookieSize.length == 2 ? 0x82 : 0x83)); // short or long form
        buff.put(cookieSize); // byte array size
        if (cookie.length > 0) {
            buff.put(cookie); // (cookie, Ber.ASN_OCTET_STR);
        }
        return buff.array();
    }

    public DirSyncControl setFlags(final int flags) {
        this.flags = flags;
        // value encoding must be regenerated to provide new flags ...
        super.value = berEncodedValue();
        return this;
    }
}
