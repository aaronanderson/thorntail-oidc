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

package com.mercer.cpsg.swarm.oidc.deployment;

import java.security.Principal;
import java.util.Map;

public abstract class OIDCPrincipal implements Principal {
	private final String name;
	private final Map<String, Object> claims;

	protected OIDCPrincipal(String name, Map<String, Object> claims) {
		this.name = name;
		this.claims = claims;
	}

	@Override
	public String getName() {
		return name;
	}

	public Map<String, Object> getClaims() {
		return claims;
	}

	@Override
	public String toString() {
		return name;
	}

	// standard OIDC claims

	public String getSubject() {
		return (String) claims.get("sub");
	}

	public String getFullName() {
		return (String) claims.get("name");
	}

	public String getFirstName() {
		return (String) claims.get("given_name");
	}

	public String getLastName() {
		return (String) claims.get("family_name");
	}

	public String getMiddleName() {
		return (String) claims.get("middle_name");
	}

	public String getNickName() {
		return (String) claims.get("nickname");
	}

	public String getPreferredUserName() {
		return (String) claims.get("preferred_username");
	}

	public String getProfile() {
		return (String) claims.get("profile");
	}

	public String getPicture() {
		return (String) claims.get("picture");
	}

	public String getWebsite() {
		return (String) claims.get("website");
	}

	public String getEmail() {
		return (String) claims.get("email");
	}

	public String isEmailVerfied() {
		return (String) claims.get("email_verified");
	}

	public String getGender() {
		return (String) claims.get("gender");
	}

	public String geBirtDate() {
		return (String) claims.get("birthdate");
	}

	public String getZoneInfo() {
		return (String) claims.get("zoneinfo");
	}

	public String getLocale() {
		return (String) claims.get("locale");
	}

	public String getPhoneNumber() {
		return (String) claims.get("phone_number");
	}

	public Boolean isPhoneNumberVerified() {
		return (Boolean) claims.get("phone_number_verified");
	}

	public String getAddress() {
		return (String) claims.get("address");
	}

	public String getUpdateAt() {
		return (String) claims.get("updated_at");
	}

}
