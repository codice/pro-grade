/*
 * #%L
 * pro-grade
 * %%
 * Copyright (C) 2013 - 2014 Ondřej Lukáš, Josef Cacek
 * %%
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
 * #L%
 */
package net.sourceforge.prograde.policy;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

/**
 * Helper class to keep privileged actions on a single place.
 * 
 * @author Josef Cacek
 */
public class SecurityActions {

    /**
     * Returns a system property value using the specified <code>key</code>.
     * 
     * @param key
     * @return
     */
    public static String getSystemProperty(final String key) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return System.getProperty(key);
                }
            });
        } else {
            return System.getProperty(key);
        }
    }

    /**
     * Returns a security property value using the specified <code>key</code>.
     * 
     * @param key
     * @see Security#getProperty(String)
     * @return
     */
    public static String getSecurityProperty(final String key) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged(new PrivilegedAction<String>() {
                public String run() {
                    return Security.getProperty(key);
                }
            });
        } else {
            return Security.getProperty(key);
        }
    }
}
