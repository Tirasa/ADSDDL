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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.naming.CommunicationException;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags.Flag;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.utils.GUID;

/**
 * A class which asserts whether the DACL (Discretionary Access Control List) of an AD object grants the principal of an
 * {@code AdRoleAssertion} all the rights which the assertion contains.<br/>
 * <br/>
 * The caller must specify the LDAP search filter which will be used to locate the given object in the domain & fetch its
 * {@code nTSecurityDescriptor} attribute, which contains the DACL. Alternatively, a constructor accepting a pre-created DACL is 
 * available. The DACL is then searched for all {@code ACE} entries which
 * are expected to satisfy {@code AceAssertions} specified by the {@code AdRoleAssertion}; the assertion is passed in to the
 * method {@linkplain doAssert}. If there are unsatisfied assertions, and the adRoleAssertion refers to a user, the evaluation is
 * repeated for all groups the user belongs to. The caller may then evaluate the result of {@linkplain doAssert} and identify
 * unsatisfied assertions by calling {@linkplain getUnsatisfiedAssertions}.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223510.aspx
 */
public class DACLAssertor {

    private static final Logger log = LoggerFactory.getLogger(DACLAssertor.class);

    /**
     * LDAP search filter for the object whose DACL will be evaluated.
     */
    private String searchFilter;

    /**
     * Pre-connected LdapContext.
     */
    private LdapContext ldapContext;

    /**
     * Whether to search the groups of the roleAssertion principal.
     */
    private boolean searchGroups;

    /**
     * The parsed DACL.
     */
    private ACL dacl;

    /**
     * List of any unsatisfied AceAssertions after {@code doAssert} runs.
     */
    private List<AceAssertion> unsatisfiedAssertions = new ArrayList<>();

    /**
     * DACLAssertor constructor.
     *
     * @param searchFilter
     *            LDAP search filter, locating an object whose DACL will be evaluated against the AdRoleAssertion. <b>NOTE: LDAP
     *            filter escaping is the caller's responsibility</b>
     * @param searchGroups
     *            whether to search groups of a user contained in the AdRoleAssertion
     * @param ldapContext
     *            the pre-connected LDAP context
     */
    public DACLAssertor(String searchFilter, boolean searchGroups, LdapContext ldapContext) {
        this.searchFilter = searchFilter;
        this.searchGroups = searchGroups;
        this.ldapContext = ldapContext;
    }

    /**
     * DACLAssertor constructor. This version takes a pre-created DACL.
     *
     * @param dacl
     *            the DACL of the object to evaluate against the AdRoleAssertion
     * @param searchGroups
     *            whether to search groups of a user contained in the AdRoleAssertion
     */
    public DACLAssertor(ACL dacl, boolean searchGroups) {
        this.dacl = dacl;
        this.searchGroups = searchGroups;
    }

    /**
     * Compares the object DACL located by the searchFilter against the specified {@code AdRoleAssertion}, and determines whether
     * that assertion's principal is granted all the rights which the assertion contains.<br/>
     * <br/>
     * When comparing ACEs of the DACL, only those of {@code AceType.ACCESS_ALLOWED_ACE_TYPE} or
     * {@code AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE} will be considered for satisfying an {@code AceAssertion} of the
     * roleAssertion.<br/>
     * <br/>
     * Once completed, any unsatisfied assertions can be obtained by calling {@linkplain getUnsatisfiedAssertions}.
     *
     * @param roleAssertion
     *            the AdRoleAssertion
     * @return true if the DACL fulfills the claims of the roleAssertion, false otherwise.
     * @throws CommunicationException
     *             if the context for searching the DACL is invalid or the domain cannot be reached
     * @throws NameNotFoundException
     *             if the DACL search fails
     * @throws NamingException
     *             if extracting the DACL fails or another JNDI issue occurs
     * @throws SizeLimitExceededException
     *             if more than one AD object found during DACL search
     */
    public boolean doAssert(AdRoleAssertion roleAssertion) throws NamingException {
        boolean result = false;

        if (roleAssertion.getPrincipal() == null) {
            log.warn("DACLAssertor.run, unable to run against a NULL principal specified in AdRoleAssertion");
            return result;
        }

        if (dacl == null) {
            getDACL();
        }

        this.unsatisfiedAssertions = findUnsatisfiedAssertions(roleAssertion);
        result = this.unsatisfiedAssertions.isEmpty() ? true : false;
        log.info("doAssert, result: {}", result);
        return result;
    }

    /**
     * Returns list of AceAssertions in the AdRoleAssertion given to {@linkplain doAssert} which are unsatisfied.
     *
     * @return list of unsatisfied AceAssertions
     */
    public List<AceAssertion> getUnsatisfiedAssertions() {
        return unsatisfiedAssertions;
    }

    /**
     * Fetches the DACL of the object which is evaluated by {@linkplain doAssert}
     *
     * @throws CommunicationException
     * @throws NameNotFoundException
     * @throws NamingException
     */
    private void getDACL() throws NamingException {
        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "name", "nTSecurityDescriptor" });

        if (ldapContext == null) {
            log.warn("getDACL, cannot search for DACL with null ldapContext");
            throw new CommunicationException("NULL ldapContext");
        }

        ldapContext.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        log.debug("getDACL, attempting to fetch SD for searchFilter: {}, ldapContext: {}", searchFilter,
                ldapContext.getNameInNamespace());
        NamingEnumeration<SearchResult> results = null;
        try {
            results = ldapContext.search("", searchFilter, controls);
            if (!results.hasMoreElements()) {
                log.warn("getDACL, searchFilter '{}' found nothing in context '{}'", searchFilter,
                        ldapContext.getNameInNamespace());
                throw new NameNotFoundException("No results found for: " + searchFilter);
            }

            SearchResult res = results.next();
            if (results.hasMoreElements()) {
                // result from search filter is not unique
                throw new SizeLimitExceededException("The search filter '{}' matched more than one AD object");
            }            
            final byte[] descbytes = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
            final SDDL sddl = new SDDL(descbytes);
            dacl = sddl.getDacl();
            log.debug("getDACL, fetched SD & parsed DACL for searchFilter: {}, ldapContext: {}", searchFilter,
                    ldapContext.getNameInNamespace());
        } finally {
            try {
                if (results != null) {
                    results.close();
                }
            } catch (NamingException e) {
                log.debug("NamingException occurred while closing results: ", e);
            }
        }
    }

    /**
     * Evaluates whether the DACL fulfills the given AdRoleAssertion and returns the list of unsatisfied AceAssertions (if any).
     *
     * If the assertor was constructed with {@code searchGroups = true} and the roleAssertion specifies a user, then all group
     * SIDs contained in the roleAssertion will be tested for potential matches in the DACL if any rights are not directly granted
     * to the user.
     *
     * @param roleAssertion
     *            the AdRoleAssertion to test
     * @return List of unsatisfied AceAssertions (if any). Empty if none.
     */
    private List<AceAssertion> findUnsatisfiedAssertions(final AdRoleAssertion roleAssertion) {
        HashMap<String, List<ACE>> acesBySIDMap = new HashMap<String, List<ACE>>();

        for (int i = 0; i < dacl.getAceCount(); i++) {
            final ACE ace = dacl.getAce(i);
            log.trace("ACE {}: {}", i, ace);
            if (ace.getSid() != null) {
                acesBySIDMap.putIfAbsent(ace.getSid().toString(), new ArrayList<ACE>());
                List<ACE> aces = acesBySIDMap.get(ace.getSid().toString());
                aces.add(ace);
            }
        }

        // Find any roleAssertion ACEs not matched in the DACL.
        // Not using Java 8 or other libs for this to keep dependencies of ADSDDL as is.
        // ------------------------------
        List<AceAssertion> unsatisfiedAssertions = new ArrayList<>(roleAssertion.getAssertions());
        SID principal = roleAssertion.getPrincipal();
        List<ACE> principalAces = acesBySIDMap.get(principal.toString());

        if (principalAces == null) {
            log.debug("findUnsatisfiedAssertions, no ACEs matching principal {} in DACL, will attempt to search member groups",
                    principal);
        } else {
            findUnmatchedAssertions(principalAces, unsatisfiedAssertions);
            log.debug(
                    "findUnsatisfiedAssertions, {} unsatisfied assertion(s) remain after checking the DACL against principal {}, searching member groups if > 0",
                    unsatisfiedAssertions.size(), principal);
        }

        if (!unsatisfiedAssertions.isEmpty() && searchGroups) {
            if (roleAssertion.isGroup()) {
                log.warn(
                        "findUnsatisfiedAssertions, unresolved assertions exist and requested to search member groups, but the principal is a group - returning");
                return unsatisfiedAssertions;
            }

            List<SID> tokenGroupSIDs = roleAssertion.getTokenGroups();
            if (tokenGroupSIDs == null) {
                log.debug(
                        "findUnsatisfiedAssertions, unresolved assertions exist and no token groups found in AdRoleAssertion - returning");
                return unsatisfiedAssertions;
            }

            int groupCount = 1;
            for (SID grpSID : tokenGroupSIDs) {
                principalAces = acesBySIDMap.get(grpSID.toString());
                if (principalAces == null) {
                    continue;
                }
                log.debug("findUnsatisfiedAssertions, {} ACEs of group {}", principalAces.size(), grpSID);
                findUnmatchedAssertions(principalAces, unsatisfiedAssertions);
                if (unsatisfiedAssertions.isEmpty()) {
                    log.info("findUnsatisfiedAssertions, all role assertions found in the DACL after searching {} group(s)",
                            groupCount);
                    break;
                }
                groupCount++;
            }
        }

        return unsatisfiedAssertions;
    }

    /**
     * Finds which AceAssertions are satisfied by the given list of ACEs, removes those from the unsatisfied list, and returns.
     * Upon returning, only the assertions still unmatched will be in the given {@code unsatisfiedAssertions} list.
     *
     * @param aces
     *            ACE list to be evaluated
     * @param unsatisfiedAssertions
     *            list of AceAssertions currently unmatched in the DACL.
     */
    private void findUnmatchedAssertions(final List<ACE> aces, List<AceAssertion> unsatisfiedAssertions) {
        List<AceAssertion> unmatchedAssertions = null;
        if (aces == null || aces.isEmpty()) {
            return;
        }

        for (ACE ace : aces) {
            long rightsMask = ace.getRights().asUInt();
            unmatchedAssertions = new ArrayList<>(unsatisfiedAssertions);
            log.debug("findUnmatchedAssertions, processing ACE: {}", ace);

            // can only match type ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT
            if (ace.getType().getValue() != AceType.ACCESS_ALLOWED_ACE_TYPE.getValue()
                    && ace.getType().getValue() != AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE.getValue()) {
                log.debug("findUnmatchedAssertions, skipping ACE with non allowed object type: {}", ace.getType().getValue());
                continue;
            }

            for (AceAssertion assertion : unmatchedAssertions) {
                long assertRight = assertion.getAceRight().asUInt();
                log.debug("findUnmatchedAssertions, assertRightMask: {}, aceRightsMask: {}", assertRight, rightsMask);
                if ((rightsMask & assertRight) == assertRight) {
                    // found a rights match
                    if (doObjectFlagsMatch(ace.getObjectFlags(), assertion.getObjectFlags())
                            && doObjectTypesMatch(ace.getObjectType(), assertion.getObjectType(), assertion.getObjectFlags())
                            && doInheritedObjectTypesMatch(ace.getInheritedObjectType(), assertion.getInheritedObjectType(),
                                    assertion.getObjectFlags())
                            && doRequiredFlagsMatch(ace.getFlags(), assertion.getRequiredFlag())
                            && !isAceExcluded(ace.getFlags(), assertion.getExcludedFlag())) {
                        log.debug("findUnmatchedAssertions, found an assertion match for: {}", assertion);
                        unsatisfiedAssertions.remove(assertion);
                    }
                }
            }
        }
    }

    /**
     * Compares the AceObjectFlags attribute of an ACE against that of an AceAssertion. If the {@code assertionObjFlags} are null,
     * a true result is returned.
     *
     * @param aceObjFlags
     *            object flags from the ACE
     * @param assertionObjFlags
     *            object flags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doObjectFlagsMatch(final AceObjectFlags aceObjFlags, final AceObjectFlags assertionObjFlags) {
        boolean res = true;
        if (assertionObjFlags != null) {
            if (aceObjFlags != null && (aceObjFlags.asUInt() & assertionObjFlags.asUInt()) == assertionObjFlags.asUInt()) {
                res = true;
            } else {
                res = false;
            }
        }
        log.debug("doObjectFlagsMatch, result: {}", res);
        return res;
    }

    /**
     * Checks whether the object type identified by the ACE matches the object type of the AceAssertion given. If the
     * {@code assertionObjFlags} are null, or they do not specify ACE_OBJECT_TYPE_PRESENT, a true result is returned.
     *
     * @param aceObjectType
     *            byte array containing the ACE objectType GUID
     * @param assertionObjectType
     *            String containing the AceAssertion objectType
     * @param assertionObjFlags
     *            AceObjectFlags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doObjectTypesMatch(byte[] aceObjectType, final String assertionObjectType,
            final AceObjectFlags assertionObjFlags) {
        boolean res = true;
        if (assertionObjFlags == null) {
            return res;
        }

        if ((assertionObjFlags.asUInt() & Flag.ACE_OBJECT_TYPE_PRESENT.getValue()) == Flag.ACE_OBJECT_TYPE_PRESENT.getValue()) {
            if (aceObjectType == null || !GUID.getGuidAsString(aceObjectType).equals(assertionObjectType)) {
                res = false;
            }
        }
        log.debug("doObjectTypesMatch, result: {}", res);
        return res;
    }

    /**
     * Checks whether the inherited object type identified by the ACE matches the inherited object type of the AceAssertion given.
     * If the {@code assertionObjFlags} are null, or they do not specify ACE_INHERITED_OBJECT_TYPE_PRESENT, a true result is
     * returned.
     *
     * @param aceInhObjectType
     *            byte array containing the ACE inheritedObjectType GUID
     * @param assertionInhObjectType
     *            String containing the AceAssertion inheritedObjectType
     * @param assertionObjFlags
     *            AceObjectFlags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doInheritedObjectTypesMatch(byte[] aceInhObjectType, final String assertionInhObjectType,
            final AceObjectFlags assertionObjFlags) {
        boolean res = true;
        if (assertionObjFlags == null) {
            return res;
        }

        if ((assertionObjFlags.asUInt()
                & Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT.getValue()) == Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT.getValue()) {
            if (aceInhObjectType == null || !GUID.getGuidAsString(aceInhObjectType).equals(assertionInhObjectType)) {
                res = false;
            }
        }
        log.debug("doInheritedObjectTypesMatch, result: {}", res);
        return res;
    }

    /**
     * Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
     * {@code requiredFlag} is null, yet the {@code aceFlags} are not (or empty), or vice versa, or they do not contain the
     * required flag, a false result is returned.
     *
     * @param aceFlags
     *            list of AceFlags from the ACE
     * @param requiredFlag
     *            AceFlag required by the AceAssertion (e.g., {@code AceFlag.CONTAINER_INHERIT_ACE})
     * @return true if match, false if not
     */
    private boolean doRequiredFlagsMatch(final List<AceFlag> aceFlags, final AceFlag requiredFlag) {
        boolean res = true;
        if (requiredFlag != null) {
            // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
            if (aceFlags == null || aceFlags.isEmpty() || !aceFlags.contains(requiredFlag)) {
                res = false;
            }
        } else if (aceFlags != null && !aceFlags.isEmpty()) {
            res = false;
        }
        log.debug("doRequiredFlagsMatch, result: {}", res);
        return res;
    }

    /**
     * Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
     * {@code excludedFlag} is null, or the {@code aceFlags} are null (or empty), or are non-null and do DO NOT contain the
     * excluded flag, a false result is returned. Otherwise, a true result is returned.
     *
     * @param aceFlags
     *            list of AceFlags from the ACE
     * @param excludedFlag
     *            AceFlag disallowed by the AceAssertion (e.g., {@code AceFlag.INHERIT_ONLY_ACE})
     * @return true if AceFlags is excluded, false if not
     */
    private boolean isAceExcluded(final List<AceFlag> aceFlags, final AceFlag excludedFlag) {
        boolean res = false;
        if (excludedFlag != null) {
            // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
            if (aceFlags != null && !aceFlags.isEmpty() && aceFlags.contains(excludedFlag)) {
                res = true;
            }
        }
        log.debug("isAceExcluded, result: {}", res);
        return res;
    }
}
