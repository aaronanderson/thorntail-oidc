/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mercer.cpsg.swarm.oidc;

import java.util.HashMap;

import org.wildfly.swarm.config.security.Flag;
import org.wildfly.swarm.config.security.SecurityDomain;
import org.wildfly.swarm.config.security.security_domain.ClassicAuthentication;
import org.wildfly.swarm.config.security.security_domain.authentication.LoginModule;
import org.wildfly.swarm.security.SecurityFraction;
import org.wildfly.swarm.spi.api.Fraction;

/**
 * @author Bob McWhirter
 */
public class OIDCFraction extends OIDC<OIDCFraction> implements Fraction {

	private boolean inhibitDefaultDatasource = false;

	public OIDCFraction inhibitDefaultDomain() {
		this.inhibitDefaultDatasource = true;
		return this;
	}

	public boolean isInhibitDefaultDatasource() {
		return inhibitDefaultDatasource;
	}

	@Override
	public void initialize(InitContext initContext) {
		if (!inhibitDefaultDatasource) {
			initContext.fraction(SecurityFraction.defaultSecurityFraction().securityDomain(new SecurityDomain("oidc-domain").classicAuthentication(new ClassicAuthentication().loginModule(new LoginModule("OIDC").code("com.mercer.cpsg.swarm.oidc.runtime.OIDCLoginModule").flag(Flag.REQUIRED).moduleOptions(new HashMap<Object, Object>() {
				{
					put("roles-claim-name", "groups");
				}
			})))));
		}
	}

}
