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

import javax.naming.ldap.BasicControl;

/**
 * The LDAP_SERVER_NOTIFICATION_OID control is used with an extended LDAP asynchronous search function to register the
 * client to be notified when changes are made to an object in Active Directory.
 */
public class NotifyControl extends BasicControl {

    private static final long serialVersionUID = -930993758829518420L;

    /**
     * LDAP_SERVER_NOTIFICATION_OID.
     */
    public static final String OID = "1.2.840.113556.1.4.528";

    /**
     * Constructor.
     */
    public NotifyControl() {
        super(OID, true, null);
    }
}
