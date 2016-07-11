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

package com.mercer.cpsg.swarm.oidc.runtime;

import java.security.Principal;
import java.security.acl.Group;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.SecurityConstants;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.callback.SecurityAssociationCallback;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import com.mercer.cpsg.swarm.oidc.OIDCPrincipal;

import net.minidev.json.JSONArray;

public class OIDCLoginModule extends AbstractServerLoginModule {
	private static final Logger LOG = Logger.getLogger(OIDCLoginModule.class.getName());

	private static final String ROLES_CLAIM_NAME = "roles-claim-name";

	private OIDCPrincipal identity = null;
	private Group[] roleSets = null;
	private String rolesClaimName = null;

	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
		super.initialize(subject, callbackHandler, sharedState, options);
		rolesClaimName = (String) options.get(ROLES_CLAIM_NAME);

	}

	public boolean login() throws LoginException {
		super.loginOk = false;

		try {
			if (checkPrincipal(sharedState.get("javax.security.auth.login.name"))) {
				return true;
			}
		} catch (Exception e) {
			LOG.log(Level.SEVERE, "", e);
		}

		if (this.callbackHandler == null) {
			throw new LoginException("No callback handler is available");
		}

		Callback callbacks[] = new Callback[1];
		callbacks[0] = new SecurityAssociationCallback();

		try {
			this.callbackHandler.handle(callbacks);
			return checkPrincipal(((SecurityAssociationCallback) callbacks[0]).getPrincipal());

		} catch (Exception e) {
			throw new LoginException("Callback Exception: " + e.getLocalizedMessage());
		}

	}

	public boolean checkPrincipal(Object identity) {
		if (identity != null && identity instanceof OIDCPrincipal) {
			super.loginOk = true;
			this.identity = (OIDCPrincipal) identity;
			Group roles = new SimpleGroup(SecurityConstants.ROLES_IDENTIFIER);
			if (identity != null && rolesClaimName != null) {
				Object rolesClaim = this.identity.getClaims().get(rolesClaimName);
				if (rolesClaim instanceof JSONArray) {
					((List<String>) rolesClaim).forEach(r -> roles.addMember(new SimplePrincipal(r)));
				}

			}
			this.roleSets = new Group[] { roles };

			return true;
		}
		return false;
	}

	@Override
	protected Principal getIdentity() {
		return identity;
	}

	@Override
	protected Group[] getRoleSets() throws LoginException {
		return roleSets;
	}

}