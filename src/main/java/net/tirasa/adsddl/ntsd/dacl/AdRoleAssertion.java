/*
 * Copyright © 2018 VMware, Inc. All Rights Reserved.
 *
 * COPYING PERMISSION STATEMENT
 * SPDX-License-Identifier: Apache-2.0
 */
package net.tirasa.adsddl.ntsd.dacl;

import java.util.List;

import net.tirasa.adsddl.ntsd.SID;

/**
 * An AD role assertion represents a claim that a given principal meets all the criteria in the given {@code AceAssertion} list.
 * These criteria are considered the requirements of a given 'role', e.g., the ability to join computers to a domain an unlimited
 * number of times can be considered to be a role.
 *
 * An instance of this class can be passed to a {@code DACLAssertor} to actually perform the assertion against the DACL
 * (Discretionary Access Control List) of an AD object.
 */
public abstract class AdRoleAssertion {

    /**
     * List of AceAssertions.
     */
    private List<AceAssertion> assertions = null;

    /**
     * SID of the principal (i.e., user or group) which is to be asserted.
     */
    private SID principal = null;

    /**
     * Whether the principal represents a group or not.
     */
    private boolean isGroup = false;

    /**
     * The tokenGroup SIDs of the principal, if a user. May be null.
     */
    private List<SID> tokenGroups = null;

    public AdRoleAssertion() {
    }

    /**
     * AdRoleAssertion constructor.
     *
     * @param assertions
     *            list of AceAssertions which make up the claims
     * @param principal
     *            the user or group SID which is to be asserted
     * @param isGroup
     *            whether the principal is a group
     * @param tokenGroups
     *            the token group SIDs of the principal (if it is a user)
     */
    public AdRoleAssertion(List<AceAssertion> assertions, SID principal, boolean isGroup, List<SID> tokenGroups) {
        this.assertions = assertions;
        this.principal = principal;
        this.isGroup = isGroup;
        this.tokenGroups = tokenGroups;
    }

    /**
     * Gets the list of assertions
     *
     * @return assertions
     */
    public List<AceAssertion> getAssertions() {
        return assertions;
    }

    /**
     * Gets the SID of the principal
     *
     * @return principal SID
     */
    public SID getPrincipal() {
        return principal;
    }

    /**
     * Whether the principal is a group
     *
     * @return true if principal is a group, false if a user
     */
    public boolean isGroup() {
        return isGroup;
    }

    /**
     * Gets the token group SIDs of the principal, may be null
     *
     * @return SIDs of the principal's token groups, if principal is a user
     */
    public List<SID> getTokenGroups() {
        return tokenGroups;
    }
}
