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
package net.sourceforge.prograde.generator;

import java.security.Permission;
import java.security.ProtectionDomain;

/**
 * Interface which is used by {@link NotifyAndAllowPolicy} to send information about denied permission and policy refresh event.
 * 
 * @author Josef Cacek
 */
public interface DeniedPermissionListener {

    /**
     * Called when policy doesn't imply permission.
     * 
     * @param pd ProtectionDomain
     * @param perm Permission
     */
    void permissionDenied(ProtectionDomain pd, Permission perm);

    /**
     * Called after the policy was refreshed.
     */
    void policyRefreshed();

}
