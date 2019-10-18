/*
 * Copyright (C) 2018 VMware, Inc.
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
/*
* Copyright © 2018-2019 VMware, Inc. All Rights Reserved.
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
 * {@code AdRoleAssertion} all the rights which the assertion contains.<br>
 * <br>
 * The caller must specify the LDAP search filter which will be used to locate the given object in the domain and fetch
 * its {@code nTSecurityDescriptor} attribute, which contains the DACL. Alternatively, a constructor accepting a 
 * pre-created DACL is available. The DACL is then searched for all {@code ACE} entries which
 * are expected to satisfy {@code AceAssertions} specified by the {@code AdRoleAssertion}; the assertion is passed in to
 * the method {@linkplain doAssert}. If there are unsatisfied assertions, and the adRoleAssertion refers to a user, the
 * evaluation is repeated for all groups the user belongs to. The caller may then evaluate the result of 
 * {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#doAssert} and identify unsatisfied assertions by calling 
 * {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#getUnsatisfiedAssertions}.<br>
 * <br>
 * Denied rights are now detected and included in the result, if they are determined to override satisfied rights.
 * Only non-inherited denials can override a right which is granted. 
 * The 'Everyone' AD group is also evaluted if constructed with {@code searchGroups = true}
 *
 * @see <a href="https://msdn.microsoft.com/en-us/library/cc223510.aspx" target="_top">cc223510</a>
 */
public class DACLAssertor {

    private static final Logger LOG = LoggerFactory.getLogger(DACLAssertor.class);

    /**
     * SID of the 'Everyone' AD group.
     */
    private static final String EVERYONE_SID = "S-1-1-0";

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
    private final boolean searchGroups;

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
     * LDAP search filter, locating an object whose DACL will be evaluated against the AdRoleAssertion. <b>NOTE: LDAP
     * filter escaping is the caller's responsibility</b>
     * @param searchGroups
     * whether to search groups of a user contained in the AdRoleAssertion
     * @param ldapContext
     * the pre-connected LDAP context
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
     * the DACL of the object to evaluate against the AdRoleAssertion
     * @param searchGroups
     * whether to search groups of a user contained in the AdRoleAssertion
     */
    public DACLAssertor(ACL dacl, boolean searchGroups) {
        this.dacl = dacl;
        this.searchGroups = searchGroups;
    }

    /**
     * Compares the object DACL located by the searchFilter against the specified {@code AdRoleAssertion}, and
     * determines whether
     * that assertion's principal is granted all the rights which the assertion contains.<br>
     * <br>
     * When comparing ACEs of the DACL, only those of {@code AceType.ACCESS_ALLOWED_ACE_TYPE} or
     * {@code AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE} will be considered for satisfying an {@code AceAssertion} of the
     * roleAssertion.<br>
     * <br>
     * Once completed, any unsatisfied assertions can be obtained by calling {@linkplain getUnsatisfiedAssertions}.
     * Denied rights are now detected and included in the result, if they are determined to override satisfied rights.
     *
     * @param roleAssertion
     * the AdRoleAssertion
     * @return true if the DACL fulfills the claims of the roleAssertion, false otherwise.
     * @throws CommunicationException
     * if the context for searching the DACL is invalid or the domain cannot be reached
     * @throws NameNotFoundException
     * if the DACL search fails
     * @throws NamingException
     * if extracting the DACL fails or another JNDI issue occurs
     * @throws SizeLimitExceededException
     * if more than one AD object found during DACL search
     */
    public boolean doAssert(AdRoleAssertion roleAssertion) throws NamingException {
        boolean result = false;

        if (roleAssertion.getPrincipal() == null) {
            LOG.warn("DACLAssertor.run, unable to run against a NULL principal specified in AdRoleAssertion");
            return result;
        }

        if (dacl == null) {
            getDACL();
        }

        this.unsatisfiedAssertions = findUnsatisfiedAssertions(roleAssertion);
        result = this.unsatisfiedAssertions.isEmpty() ? true : false;
        LOG.info("doAssert, result: {}", result);
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
     * Fetches the DACL of the object which is evaluated by
     * {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#doAssert}
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
            LOG.warn("getDACL, cannot search for DACL with null ldapContext");
            throw new CommunicationException("NULL ldapContext");
        }

        ldapContext.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });

        LOG.debug("getDACL, attempting to fetch SD for searchFilter: {}, ldapContext: {}", searchFilter,
                ldapContext.getNameInNamespace());
        NamingEnumeration<SearchResult> results = null;
        try {
            results = ldapContext.search("", searchFilter, controls);
            if (!results.hasMoreElements()) {
                LOG.warn("getDACL, searchFilter '{}' found nothing in context '{}'", searchFilter,
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
            LOG.debug("getDACL, fetched SD & parsed DACL for searchFilter: {}, ldapContext: {}", searchFilter,
                    ldapContext.getNameInNamespace());
        } finally {
            try {
                if (results != null) {
                    results.close();
                }
            } catch (NamingException e) {
                LOG.debug("NamingException occurred while closing results: ", e);
            }
        }
    }

    /**
     * Evaluates whether the DACL fulfills the given AdRoleAssertion and returns the list of unsatisfied AceAssertions
     * (if any).<br>
     * <br>
     * If the assertor was constructed with {@code searchGroups = true} and the roleAssertion specifies a user, then
     * all group SIDs contained in the roleAssertion will be tested for potential matches in the DACL if any rights are
     * not directly granted to the user. Also, the 'Everyone' AD group will also be scanned.<br>
     * <br>
     * Denied rights are now detected and included in the resulting list.
     *
     * @param roleAssertion
     * the AdRoleAssertion to test
     * @return List of unsatisfied AceAssertions (if any). Empty if none.
     */
    private List<AceAssertion> findUnsatisfiedAssertions(final AdRoleAssertion roleAssertion) {
        HashMap<String, List<ACE>> acesBySIDMap = new HashMap<String, List<ACE>>();

        for (int i = 0; i < dacl.getAceCount(); i++) {
            final ACE ace = dacl.getAce(i);
            LOG.trace("ACE {}: {}", i, ace);
            if (ace.getSid() != null) {
                if (!acesBySIDMap.containsKey(ace.getSid().toString())) {
                    acesBySIDMap.put(ace.getSid().toString(), new ArrayList<ACE>());
                }
                List<ACE> aces = acesBySIDMap.get(ace.getSid().toString());
                aces.add(ace);
            }
        }

        // Find any roleAssertion ACEs not matched in the DACL.
        // Not using Java 8 or other libs for this to keep dependencies of ADSDDL as is.
        // ------------------------------
        List<AceAssertion> unsatisfiedAssertions = new ArrayList<>(roleAssertion.getAssertions());
        List<AceAssertion> deniedAssertions = new ArrayList<>();
        SID principal = roleAssertion.getPrincipal();
        List<ACE> principalAces = acesBySIDMap.get(principal.toString());

        if (principalAces == null) {
            LOG.debug("findUnsatisfiedAssertions, no ACEs matching principal {} in DACL, will attempt to search member "
                    + "groups if requested", principal);
        } else {
            findUnmatchedAssertions(principalAces, unsatisfiedAssertions, deniedAssertions, roleAssertion.getAssertions());
            LOG.debug(
                    "findUnsatisfiedAssertions, {} unsatisfied assertion(s) remain after checking the DACL against "
                    + "principal {}, and {} denial(s); searching member groups if requested and existent",
                    unsatisfiedAssertions.size(), principal, deniedAssertions.size());
        }

        // There may be denials on groups even if we resolved all assertions - search groups if specified
        if (searchGroups) {
            if (roleAssertion.isGroup()) {
                LOG.warn(
                        "findUnsatisfiedAssertions, requested to search member groups, but the principal is a group - "
                        + "running Everyone group scan before returning");
                doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.getAssertions());
                mergeDenials(unsatisfiedAssertions, deniedAssertions);
                return unsatisfiedAssertions;
            }

            List<SID> tokenGroupSIDs = roleAssertion.getTokenGroups();
            if (tokenGroupSIDs == null) {
                LOG.debug(
                        "findUnsatisfiedAssertions, no token groups found in AdRoleAssertion - running Everyone group "
                        + "scan before returning");
                doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.getAssertions());
                mergeDenials(unsatisfiedAssertions, deniedAssertions);
                return unsatisfiedAssertions;
            }

            int groupCount = 1;
            for (SID grpSID : tokenGroupSIDs) {
                principalAces = acesBySIDMap.get(grpSID.toString());
                if (principalAces == null) {
                    continue;
                }
                int unsatCount = unsatisfiedAssertions.size();
                LOG.debug("findUnsatisfiedAssertions, {} unsatisfied(s); {} ACE(s) of group {} to scan",
                            unsatCount, principalAces.size(), grpSID);
                findUnmatchedAssertions(principalAces, unsatisfiedAssertions, deniedAssertions, roleAssertion.getAssertions());
                if (unsatisfiedAssertions.isEmpty() && unsatCount > 0) {
                    LOG.info("findUnsatisfiedAssertions, all role assertions found in in DACL after searching {} "
                            + "group(s); scanning for denials", groupCount);
                }
                groupCount++;
            }

            doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.getAssertions());
        }

        mergeDenials(unsatisfiedAssertions, deniedAssertions);

        return unsatisfiedAssertions;
    }

    private void doEveryoneGroupScan(final HashMap<String, List<ACE>> acesBySIDMap, final List<AceAssertion> unsatisfiedAssertions,
            final List<AceAssertion> deniedAssertions, final List<AceAssertion> roleAssertions) {
        LOG.debug("doEveryoneGroupScan, starting");
        List<ACE> everyoneACEs = acesBySIDMap.get(EVERYONE_SID);
        findUnmatchedAssertions(everyoneACEs, unsatisfiedAssertions, deniedAssertions, roleAssertions);
    }

    /**
     * Finds which AceAssertions are satisfied by the given list of ACEs, and removes those from the unsatisfied list.
     * Also finds ACEs which are explicitly denied and adds those to the deniedAssertions list if they match any
     * roleAssertions. Upon returning, only the assertions still unmatched will be in the given 
     * {@code unsatisfiedAssertions} list, and denials will accumulate in the {@code deniedAssertions} list.
     *
     * @param aces
     * ACE list to be evaluated
     * @param unsatisfiedAssertions
     * list of AceAssertions currently unmatched in the DACL.
     * @param deniedAssertions
     * list of AceAssertions denied in the DACL.
     * @param roleAssertions
     * the AceAssertions from the AdRoleAssertion
     */
    private void findUnmatchedAssertions(final List<ACE> aces, final List<AceAssertion> unsatisfiedAssertions,
            final List<AceAssertion> deniedAssertions, final List<AceAssertion> roleAssertions) {
        if (aces == null || aces.isEmpty()) {
            return;
        }

        for (ACE ace : aces) {
            long rightsMask = ace.getRights().asUInt();
            LOG.debug("findUnmatchedAssertions, processing ACE: {}", ace);

            boolean isDenial = false;
            if (ace.getType().getValue() == AceType.ACCESS_DENIED_ACE_TYPE.getValue()
                    || ace.getType().getValue() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE.getValue()) {
                LOG.debug("findUnmatchedAssertions, found denial ACE type: {} ", ace.getType().name());
                isDenial = true;
            }

            // can only match type ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT, if not a denial
            if (!isDenial && ace.getType().getValue() != AceType.ACCESS_ALLOWED_ACE_TYPE.getValue()
                    && ace.getType().getValue() != AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE.getValue()) {
                LOG.debug("findUnmatchedAssertions, skipping ACE with non allowed object type: {}",
                        ace.getType().getValue());
                continue;
            }

            for (AceAssertion assertion : roleAssertions) {
                long assertRight = assertion.getAceRight().asUInt();
                LOG.debug("findUnmatchedAssertions, assertRightMask: {}, aceRightsMask: {}", assertRight, rightsMask);
                boolean isMatch = false;
                if ((rightsMask & assertRight) == assertRight) {
                    // found a rights match
                    if (doObjectFlagsMatch(ace.getObjectFlags(), assertion.getObjectFlags())
                            && doObjectTypesMatch(
                                    ace.getObjectType(),
                                    assertion.getObjectType(),
                                    assertion.getObjectFlags())
                            && doInheritedObjectTypesMatch(
                                    ace.getInheritedObjectType(),
                                    assertion.getInheritedObjectType(),
                                    assertion.getObjectFlags())
                            && doRequiredFlagsMatch(ace.getFlags(), assertion.getRequiredFlag(), isDenial)
                            && !isAceExcluded(ace.getFlags(), assertion.getExcludedFlag(), isDenial)) {
                        isMatch = true;
                    }
                }
                if (isMatch) {
                    if (!isDenial) {
                        LOG.debug("findUnmatchedAssertions, found an assertion match for: {}", assertion);
                        unsatisfiedAssertions.remove(assertion);
                    } else {
                        LOG.debug("findUnmatchedAssertions, found an assertion DENIAL for: {}", assertion);
                        addDeniedAssertion(deniedAssertions, assertion);
                    }
                }
            }
        }
    }

    /**
     * This routine adds the deniedAssertion to the given list of them, if not already present.
     * Not using {@code Set.add} which relies on the AceAssertion equals method, because of the possible variance
     * in AceAssertion properties besides the AceRights, which do not matter for purposes of tracking the denials.
     * 
     * @param deniedAssertions
     * the list of already denied assertions
     * @param assertion
     * the assertion to add if not present in deniedAssertions
     */
    private void addDeniedAssertion(final List<AceAssertion> deniedAssertions, final AceAssertion assertion) {
        long deniedRight = assertion.getAceRight().asUInt();
        boolean found = false;
        for (AceAssertion a : deniedAssertions) {
            if ((a.getAceRight().asUInt() & deniedRight) == deniedRight) {
                found = true;
                break;
            }
       }
       if (!found) {
           deniedAssertions.add(assertion);
       }
    }

    /**
     * This routine merges deniedAssertions into the unsatisfiedAssertions, avoiding duplicates.
     *
     * @param unsatisfiedAssertions
     * the list of unsatisifed assertions
     * @param deniedAssertions
     * list of denied assertions
     */
    private void mergeDenials(final List<AceAssertion> unsatisfiedAssertions, final List<AceAssertion> deniedAssertions) {
        List<AceAssertion> toAddList = new ArrayList<>();
        for (AceAssertion denial : deniedAssertions) {
            boolean found = false;
            for (AceAssertion unsat : unsatisfiedAssertions) {
                if (unsat.getAceRight().asUInt() == denial.getAceRight().asUInt()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                toAddList.add(denial);
            }
        }

        unsatisfiedAssertions.addAll(toAddList);
        LOG.debug("mergeDenials, finished with {} assertion(s) unsatisfied", unsatisfiedAssertions.size());
    }

    /**
     * Compares the AceObjectFlags attribute of an ACE against that of an AceAssertion. If the {@code assertionObjFlags}
     * are null, a true result is returned.<br>
     * <br>
     * If the {@code assertionObjFlags} are not null, then either the {@code aceObjFlags} must be a match, or they must
     * not be set. The not set case is deemed a match because MS AD documentation states that if an object type
     * (referred to by the flags) is also empty, then the ACE controls the ability to perform operations of the
     * given access right on all object classes. In this case, the decision about the ACE matching (regarding the object)
     * is left up to the {@linkplain doObjectTypesMatch} and {@linkplain doInheritedObjectTypesMatch} methods.<br>
     * <br>
     * An ACE will appear without object flags when it is for "Full Control" permissions.
     *
     * @param aceObjFlags
     * object flags from the ACE
     * @param assertionObjFlags
     * object flags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doObjectFlagsMatch(final AceObjectFlags aceObjFlags, final AceObjectFlags assertionObjFlags) {
        if (assertionObjFlags != null && aceObjFlags != null) {
            LOG.debug("doObjectFlagsMatch, assertionObjFlags: {}, aceObjFlags: {}", assertionObjFlags.asUInt(), aceObjFlags.asUInt());
        } else if (assertionObjFlags != null) {
            LOG.debug("doObjectFlagsMatch, assertionObjFlags: {}, aceObjFlags: null", assertionObjFlags.asUInt());
        } else if (aceObjFlags != null) {
            LOG.debug("doObjectFlagsMatch, assertionObjFlags: null, aceObjFlags: {}", aceObjFlags.asUInt());
        }
        boolean res = true;
        if (assertionObjFlags != null) {
            if (aceObjFlags != null
                    && (aceObjFlags.asUInt() & assertionObjFlags.asUInt()) == assertionObjFlags.asUInt()) {
                res = true;
            } else if (aceObjFlags == null || aceObjFlags.asUInt() == 0) {
                // MS docs state that if the object type is _not_ present - which is hinted at by presence of object flags -
                // then the ACE controls that right on all object classes/attributes of such objects.
                // So defer ultimate decision to object/inherited object type matching.
                res = true;
            } else {
                res = false;
            }
        }
        LOG.debug("doObjectFlagsMatch (or may be ignored), result: {}", res);
        return res;
    }

    /**
     * Checks whether the object type identified by the ACE matches the object type of the AceAssertion given. If the
     * {@code assertionObjFlags} are null, or they do not specify ACE_OBJECT_TYPE_PRESENT, a true result is returned.
     *
     * @param aceObjectType
     * byte array containing the ACE objectType GUID
     * @param assertionObjectType
     * String containing the AceAssertion objectType
     * @param assertionObjFlags
     * AceObjectFlags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doObjectTypesMatch(byte[] aceObjectType, final String assertionObjectType,
            final AceObjectFlags assertionObjFlags) {
        boolean res = true;
        if (assertionObjFlags == null) {
            return res;
        }

        if ((assertionObjFlags.asUInt()
                & Flag.ACE_OBJECT_TYPE_PRESENT.getValue()) == Flag.ACE_OBJECT_TYPE_PRESENT.getValue()) {
            if (aceObjectType != null && !GUID.getGuidAsString(aceObjectType).equals(assertionObjectType)) {
                res = false;
            }
        }
        LOG.debug("doObjectTypesMatch (or may be ignored), result: {}", res);
        return res;
    }

    /**
     * Checks whether the inherited object type identified by the ACE matches the inherited object type of the
     * AceAssertion given. If the {@code assertionObjFlags} are null, or they do not specify
     * ACE_INHERITED_OBJECT_TYPE_PRESENT, a true result is returned.
     *
     * @param aceInhObjectType
     * byte array containing the ACE inheritedObjectType GUID
     * @param assertionInhObjectType
     * String containing the AceAssertion inheritedObjectType
     * @param assertionObjFlags
     * AceObjectFlags from the AceAssertion
     * @return true if match, false if not
     */
    private boolean doInheritedObjectTypesMatch(byte[] aceInhObjectType, final String assertionInhObjectType,
            final AceObjectFlags assertionObjFlags) {
        boolean res = true;
        if (assertionObjFlags == null) {
            return res;
        }

        if ((assertionObjFlags.asUInt()
                & Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT.getValue())
                == Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT.getValue()) {
            if (aceInhObjectType != null && !GUID.getGuidAsString(aceInhObjectType).equals(assertionInhObjectType)) {
                res = false;
            }
        }
        LOG.debug("doInheritedObjectTypesMatch (or may be ignored), result: {}", res);
        return res;
    }

    /**
     * Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
     * {@code requiredFlag} is null, yet the {@code aceFlags} are not (or empty), or vice versa, or they DO NOT contain
     * the required flag, a false result is returned.
     *
     * @param aceFlags
     * list of AceFlags from the ACE
     * @param requiredFlag
     * AceFlag required by the AceAssertion (e.g., {@code AceFlag.CONTAINER_INHERIT_ACE})
     * @param isDenial
     * whether the AceType is a denial, in which case the aceFlags must not contain {@code AceFlag.INHERITED_ACE}
     * and the requiredFlag is ignored.  
     * @return true if match, false if not
     */
    private boolean doRequiredFlagsMatch(final List<AceFlag> aceFlags, final AceFlag requiredFlag, final boolean isDenial) {
        boolean res = true;
        if (isDenial) {
            // If the AceType is denial, the flags must NOT contain the inherited flag. Such denials are ineffective
            // when countered by an allowed right, so we only consider non-inherited denials as a match.
            if (aceFlags == null || !aceFlags.contains(AceFlag.INHERITED_ACE)) {
                res = true;
            } else {
                res = false;
            }
        } else if (requiredFlag != null) {
            // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
            if (aceFlags == null || aceFlags.isEmpty() || !aceFlags.contains(requiredFlag)) {
                res = false;
            }
        } else if (aceFlags != null && !aceFlags.isEmpty()) {
            res = false;
        }
        LOG.debug("doRequiredFlagsMatch, result: {}", res);
        return res;
    }

    /**
     * Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
     * {@code excludedFlag} is null, or the {@code aceFlags} are null (or empty), or are non-null and do DO NOT contain
     * the excluded flag, a false result is returned. Otherwise, a true result is returned.
     *
     * @param aceFlags
     * list of AceFlags from the ACE
     * @param excludedFlag
     * AceFlag disallowed by the AceAssertion (e.g., {@code AceFlag.INHERIT_ONLY_ACE})
     * @param isDenial
     * whether the AceType is a denial, in which case the excludedFlag evaluation is skipped
     * @return true if AceFlags is excluded, false if not
     */
    private boolean isAceExcluded(final List<AceFlag> aceFlags, final AceFlag excludedFlag, final boolean isDenial) {
        boolean res = false;
        if (excludedFlag != null && !isDenial) {
            // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
            if (aceFlags != null && !aceFlags.isEmpty() && aceFlags.contains(excludedFlag)) {
                res = true;
            }
        }
        LOG.debug("isAceExcluded, result: {}", res);
        return res;
    }
}
