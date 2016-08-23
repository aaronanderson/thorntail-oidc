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

import java.io.Serializable;
import java.util.List;

public class OIDC<T extends OIDC<T>> implements Serializable {

	private String context = "/oidc";
	private List<Realm> realms = new java.util.ArrayList<>();

	public OIDC() {

	}
	

	@SuppressWarnings("unchecked")
	public T context(String context) {
		this.context = context.startsWith("/") ? context : ("/" + context);
		return (T) this;
	}

	public List<Realm> listRealms() {
		return realms;
	}

	@SuppressWarnings("unchecked")
	public T realms(List<Realm> value) {
		this.realms = value;
		return (T) this;
	}

	@SuppressWarnings("unchecked")
	public T realm(Realm value) {
		this.realms.add(value);
		return (T) this;
	}

	@SuppressWarnings("unchecked")
	public T realm(String childKey, RealmConsumer consumer) {
		Realm child = new Realm(childKey);
		if (consumer != null) {
			consumer.accept(child);
		}
		realm(child);
		return (T) this;
	}

	public String getContext() {
		return context;
	}

	public static class Realm {
		private String name;
		private IdentityProvider provider;

		@SuppressWarnings("unused")
		private Realm() {
		}

		public Realm(String name) {
			this.name = name;
		}

		public String getName() {
			return this.name;
		}

		public IdentityProvider getProvider() {
			return provider;
		}

		public Realm provider(IdentityProvider value) {
			this.provider = value;
			return this;
		}

		public Realm provider(String childKey, IdentityProviderConsumer consumer) {
			IdentityProvider child = new IdentityProvider(childKey);
			if (consumer != null) {
				consumer.accept(child);
			}
			provider(child);
			return this;
		}

	}

	public static class IdentityProvider {
		private String name;

		private String clientId;
		private String clientSecret;
		private String scope = "openid profile";
		private String responseType = "id_token";
		private int clockSkew = 30;
		private boolean checkNonce = true;
		private String claims;
		private String metadataURL;
		private String issuer;
		private String authURL;
		private String tokenURL;
		private String userInfoURL;
		private String jwsRSAKeys;

		@SuppressWarnings("unused")
		private IdentityProvider() {
		}

		public IdentityProvider(String name) {
			this.name = name;
		}

		public String getName() {
			return this.name;
		}

		public String getClientId() {
			return clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getClientSecret() {
			return clientSecret;
		}

		public void setClientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
		}

		public String getResponseType() {
			return responseType;
		}

		public String getScope() {
			return scope;
		}

		public void setScope(String scope) {
			this.scope = scope;
		}

		public void setResponseType(String responseType) {
			this.responseType = responseType;
		}

		public int getClockSkew() {
			return clockSkew;
		}

		public void setClockSkew(int clockSkew) {
			this.clockSkew = clockSkew;
		}

		public boolean isCheckNonce() {
			return checkNonce;
		}

		public void setCheckNonce(boolean checkNonce) {
			this.checkNonce = checkNonce;
		}

		public String getClaims() {
			return claims;
		}

		public void setClaims(String claims) {
			this.claims = claims;
		}

		public String getMetadataURL() {
			return metadataURL;
		}

		public void setMetadataURL(String metadataURL) {
			this.metadataURL = metadataURL;
		}

		public String getIssuer() {
			return issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

		public String getAuthURL() {
			return authURL;
		}

		public void setAuthURL(String authURL) {
			this.authURL = authURL;
		}

		public String getTokenURL() {
			return tokenURL;
		}

		public void setTokenURL(String tokenURL) {
			this.tokenURL = tokenURL;
		}

		public String getUserInfoURL() {
			return userInfoURL;
		}

		public void setUserInfoURL(String userInfoURL) {
			this.userInfoURL = userInfoURL;
		}

		public String getJwsRSAKeys() {
			return jwsRSAKeys;
		}

		public void setJwsRSAKeys(String jwsRSAKeys) {
			this.jwsRSAKeys = jwsRSAKeys;
		}

	}

	@FunctionalInterface
	public static interface IdentityProviderConsumer {

		void accept(IdentityProvider value);

		default IdentityProviderConsumer andThen(IdentityProviderConsumer after) {
			return (c) -> {
				this.accept(c);
				after.accept(c);
			};
		}
	}

	@FunctionalInterface
	public static interface RealmConsumer {

		void accept(Realm value);

		default RealmConsumer andThen(RealmConsumer after) {
			return (c) -> {
				this.accept(c);
				after.accept(c);
			};
		}
	}

}
