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
package net.tirasa.adsddl.it;

import java.io.IOException;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

public abstract class AbstractTest extends net.tirasa.adsddl.unit.AbstractTest {

    private static final long serialVersionUID = 1L;

    protected static LdapContext ctx;

    protected static String baseContext;

    protected static String searchFilter;

    @BeforeClass
    @SuppressWarnings("unchecked")
    public static void setUpConnection() throws IOException {
        final Properties prop = new Properties();
        prop.load(AbstractTest.class.getResourceAsStream("/conf.properties"));

        @SuppressWarnings({ "UseOfObsoleteCollectionType", "rawtypes" })
        final java.util.Hashtable env = new java.util.Hashtable();

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        //set security credentials, note using simple cleartext authentication
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put("java.naming.ldap.version", "3");
        env.put(Context.SECURITY_PRINCIPAL, prop.getProperty("principal"));
        env.put(Context.SECURITY_CREDENTIALS, prop.getProperty("credentials"));
        env.put(Context.SECURITY_PROTOCOL, "ssl");
        env.put("java.naming.ldap.factory.socket", "net.tirasa.adsddl.utils.DummySocketFactory");
        env.put("java.naming.ldap.attributes.binary", "nTSecurityDescriptor objectSID");

        env.put(Context.REFERRAL, "follow");

        //connect to my domain controller
        env.put(Context.PROVIDER_URL, prop.getProperty("url"));

        try {
            // Create the initial directory context
            ctx = new InitialLdapContext(env, null);
        } catch (NamingException e) {
            log.error("Error initializing test context", e);
            Assert.fail(e.getMessage());
        }

        baseContext = prop.getProperty("baseContext");
        searchFilter = prop.getProperty("searchFilter");
    }

    @AfterClass
    public static void close() throws NamingException {
        ctx.close();
    }
}
