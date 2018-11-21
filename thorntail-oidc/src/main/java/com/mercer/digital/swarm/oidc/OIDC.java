

package com.mercer.digital.swarm.oidc;


import java.io.Serializable;
import java.util.List;

import com.nimbusds.jwt.JWTClaimsSet;

public class OIDC implements Serializable {

	private String context = "/oidc";
	private List<Realm> realms = new java.util.ArrayList<>();

	private static OIDC INSTANCE = new OIDC();

	private OIDC() {

	}

	public static OIDC getInstance() {
		return INSTANCE;
	}

	@SuppressWarnings("unchecked")
	public OIDC context(String context) {
		this.context = context.startsWith("/") ? context : ("/" + context);
		return this;
	}

	public List<Realm> listRealms() {
		return realms;
	}

	@SuppressWarnings("unchecked")
	public OIDC realms(List<Realm> value) {
		this.realms = value;
		return this;
	}

	@SuppressWarnings("unchecked")
	public OIDC realm(Realm value) {
		this.realms.add(value);
		return this;
	}

	@SuppressWarnings("unchecked")
	public OIDC realm(String childKey, RealmConsumer consumer) {
		Realm child = new Realm(childKey);
		if (consumer != null) {
			consumer.accept(child);
		}
		realm(child);
		return this;
	}

	public String getContext() {
		return context;
	}

	public static class Realm {
		private String name;
		private JWTClaimsSet defaultClaimSet;
		private List<IdentityProvider> providers = new java.util.ArrayList<>();

		@SuppressWarnings("unused")
		private Realm() {
		}

		public Realm(String name) {
			this.name = name;
		}

		public String getName() {
			return this.name;
		}
		
		public JWTClaimsSet getDefaultClaimSet() {
			return defaultClaimSet;
		}

		public Realm defaultClaimSet(JWTClaimsSet defaultClaimSet) {
			this.defaultClaimSet = defaultClaimSet;
			return this;
		}
		
		public List<IdentityProvider> listProviders() {
			return providers;
		}

		public Realm providers(List<IdentityProvider> providers) {
			this.providers = providers;
			return this;
		}
		
		public Realm provider(IdentityProvider provider) {
			providers.add( provider);
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
