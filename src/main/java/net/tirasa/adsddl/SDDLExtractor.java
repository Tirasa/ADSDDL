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
package net.tirasa.adsddl;

import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.ACL;
import net.tirasa.adsddl.ntsd.data.AceRight;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.AceFlag;
import net.tirasa.adsddl.ntsd.utils.SignedInt;

import java.io.IOException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.data.AceObjectFlag;
import net.tirasa.adsddl.ntsd.data.SDFlagsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SDDLExtractor {

    private static final long serialVersionUID = 1L;

    private static final Logger log = LoggerFactory.getLogger(SDDLExtractor.class);

    @SuppressWarnings("UseOfObsoleteCollectionType")
    private java.util.Hashtable env = new java.util.Hashtable();

    protected LdapContext ctx;

    private String domain = "tirasa.net";

    private String domainDN = "DC=tirasa,DC=net";

    private String adminName = "pocadmin@" + domain;

    private String adminPassword = "Password1";

    private String userName = "cn=ADClientTestCreate,cn=Users," + domainDN;

    private String url = "ldaps://11.10.10.4:636";

    public String[] control = {
        "SR", "RM", "PS", "PD", "SI", "DI", "SC", "DC", "DT", "SS", "SD", "SP", "DD", "DP", "GD", "OD" };

    public SDDLExtractor() throws Exception {
        init();
    }

    public static void main(String[] args) {
        try {

            final SDDLExtractor client = new SDDLExtractor();
            client.search();

        } catch (Exception e) {
            log.error("Error extracting SDDL", e);
        }
    }

    private void init() throws NamingException, IOException {
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        //set security credentials, note using simple cleartext authentication
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put("java.naming.ldap.version", "3");
        env.put(Context.SECURITY_PRINCIPAL, adminName);
        env.put(Context.SECURITY_CREDENTIALS, adminPassword);
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        env.put("java.naming.ldap.factory.socket", "net.tirasa.adsddl.DummySocketFactory");
        env.put("java.naming.ldap.attributes.binary", "nTSecurityDescriptor");

        env.put(Context.REFERRAL, "follow");

        //connect to my domain controller
        env.put(Context.PROVIDER_URL, url);

        // Create the initial directory context
        ctx = new InitialLdapContext(env, null);
    }

    private void search() throws Exception {

        final SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

        final String filter = "(&(objectclass=user)(sAMAccountName=testmb))";

        ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004 + 0x00000008) });

        final NamingEnumeration<SearchResult> results = ctx.search(domainDN, filter, controls);

        while (results.hasMore()) {
            final SearchResult res = results.next();
            final SDDL sddl = new SDDL((byte[]) res.getAttributes().get("nTSecurityDescriptor").get());

            log.info("Revision: {}", Hex.get(sddl.getRevision()));

            log.info("Control flags: ");
            final boolean[] controlFlag = SignedInt.getBits(sddl.getControlFlags());

            int count = 0;
            for (boolean flag : controlFlag) {
                if (flag) {
                    log.info(" - {}", control[count]);
                }
                count++;
            }

            log.info("OffsetOwner: " + sddl.getOffsetOwner());
            log.info("OffsetGroup: " + sddl.getOffsetGroup());
            log.info("OffsetSacl: " + sddl.getOffsetSACL());
            log.info("OffsetDacl: " + sddl.getOffsetDACL());

            if (sddl.getOffsetOwner() > 0) {
                // retrieve owner sid
                log.info("Owner: {}", Hex.get(sddl.getOwner().getIdentifierAuthority()));
            }

            if (sddl.getOffsetGroup() > 0) {
                // retrieve owner sid
                log.info("Group: {}", Hex.get(sddl.getGroup().getIdentifierAuthority()));
            }

            if (sddl.getOffsetSACL() > 0) {
                log.info("------------------------------------------");
                log.info("SACL ");
                log.info("------------------------------------------");
                final ACL acl = sddl.getSacl();
                printACL(acl);
            }

            if (sddl.getOffsetDACL() > 0) {
                log.info("------------------------------------------");
                log.info("DACL ");
                log.info("------------------------------------------");
                final ACL acl = sddl.getDacl();
                printACL(acl);
            }
        }
    }

    private void printACL(final ACL acl) {

        log.info("Acl Revision: {}", acl.getRevision().name());
        log.info("Acl Size (bytes): {}", SignedInt.getInt(acl.getSize()));

        int aceCount = SignedInt.getInt(acl.getAceCount());
        log.info("Ace Count: {}", aceCount);

        for (int i = 0; i < aceCount; i++) {
            log.info("------------------------------------------");
            log.info("ACE " + i);
            log.info("------------------------------------------");
            final ACE ace = acl.getAce(i);
            printACE(ace);
        }
    }

    private void printACE(final ACE ace) {
        log.info("AceType: {}", ace.getType().name());
        log.info("AceFlags: ");
        for (AceFlag flag : ace.getFlags()) {
            log.info(" - {}", flag);
        }

        int aceSize = ace.getSize();
        log.info("Ace Size (bytes): {}", aceSize);

        log.info("Ace Rights: ");
        int others = 0;
        for (AceRight right : ace.getRights()) {
            if (AceRight.OTHERS == right) {
                others = right.getValue();
            } else {
                log.info(" - {}", right.name());
            }
        }

        if (others != 0) {
            log.info(" - OTHERS({})", Hex.get(SignedInt.getBytes(others)));
        }

        if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            log.info("Flags: ");
            for (AceObjectFlag flag : ace.getObjectFlags()) {
                log.info(" - {}", flag.name());
            }

            if (ace.getObjectFlags().contains(AceObjectFlag.ACE_OBJECT_TYPE_PRESENT)) {
                log.info("ObjectType: {}", GUID.getGuidAsString(ace.getObjectType()));
            }

            if (ace.getObjectFlags().contains(AceObjectFlag.ACE_INHERITED_OBJECT_TYPE_PRESENT)) {
                log.info("InheritedObjectType: {}", GUID.getGuidAsString(ace.getInheritedObjectType()));
            }
        }

        final SID sid = ace.getSid();

        log.info("SID Revision: {}", Hex.get(sid.getRevision()));

        int subAuthCount = SignedInt.getInt(sid.getSubAuthorityCount());
        log.info("SID Sub Authorities Count: {}", subAuthCount);
        log.info("SID Identifier Authority: {}", Hex.get(sid.getIdentifierAuthority()));
        log.info("SID Sub Authorities: ");
        for (byte[] sub : sid.getSubAuthorities()) {
            log.info(" - {}", Hex.get(sub));
        }
    }
}
