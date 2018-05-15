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
/*
 * Copyright © 2018 VMware, Inc. All Rights Reserved.
 *
 * COPYING PERMISSION STATEMENT
 * SPDX-License-Identifier: Apache-2.0
 */
package net.tirasa.adsddl.ntsd.dacl;

import java.util.Arrays;
import java.util.List;

import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags.Flag;
import net.tirasa.adsddl.ntsd.data.AceRights;

/**
 * Represents an {@linkplain AdRoleAssertion} which specifies the criteria required to join computers to an AD domain without any
 * restrictions.
 */
public class DomainJoinRoleAssertion extends AdRoleAssertion {

    /**
     * Schema GUID of "CN=Computer,CN=Schema,CN=Configuration" objects
     */
    protected static final String COMPUTER_SCHEMA_ID_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2";

    /**
     * Schema GUID of "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration" extended right (aka "reset password")
     */
    protected static final String RESET_PASSWORD_CR_GUID = "00299570-246d-11d0-a768-00aa006e0529";

    protected static final AceAssertion createComputer = new AceAssertion(AceRights.parseValue(0x00000001),
            new AceObjectFlags(Flag.ACE_OBJECT_TYPE_PRESENT), COMPUTER_SCHEMA_ID_GUID, null, AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion deleteComputer = new AceAssertion(AceRights.parseValue(0x00000002),
            new AceObjectFlags(Flag.ACE_OBJECT_TYPE_PRESENT), COMPUTER_SCHEMA_ID_GUID, null, AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion listContents = new AceAssertion(AceRights.parseValue(0x00000004), null, null, null,
            AceFlag.CONTAINER_INHERIT_ACE, AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion readProperties = new AceAssertion(AceRights.parseValue(0x00000010), null, null, null,
            AceFlag.CONTAINER_INHERIT_ACE, AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion writeProperties = new AceAssertion(AceRights.parseValue(0x00000020), null, null, null,
            AceFlag.CONTAINER_INHERIT_ACE, AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion readPermissions = new AceAssertion(AceRights.parseValue(0x00020000), null, null, null,
            AceFlag.CONTAINER_INHERIT_ACE, AceFlag.INHERIT_ONLY_ACE);
    protected static final AceAssertion resetPassword = new AceAssertion(
            AceRights.parseValue(AceRights.ObjectRight.CR.getValue()),
            new AceObjectFlags(Flag.ACE_OBJECT_TYPE_PRESENT, Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT), RESET_PASSWORD_CR_GUID,
            COMPUTER_SCHEMA_ID_GUID, AceFlag.CONTAINER_INHERIT_ACE, null);

    protected static final AceAssertion[] domainJoinAssertions = { createComputer, deleteComputer, listContents, readProperties, writeProperties, readPermissions, resetPassword };

    /**
     * DomainJoinRoleAssertion constructor
     *
     * @param principal
     *            SID of the user or group
     * @param isGroup
     *            whether the principal is a group
     * @param tokenGroups
     *            list of token group SIDs which should be searched if the principal itself does not meet all the criteria (when
     *            the principal is a user). May be null.
     */
    public DomainJoinRoleAssertion(SID principal, boolean isGroup, List<SID> tokenGroups) {
        super(Arrays.asList(domainJoinAssertions), principal, isGroup, tokenGroups);
    }
}
