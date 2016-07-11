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

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.AccessController;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.wildfly.extension.undertow.security.AccountImpl;

import com.mercer.cpsg.swarm.oidc.OIDC;
import com.mercer.cpsg.swarm.oidc.OIDC.IdentityProvider;
import com.mercer.cpsg.swarm.oidc.OIDC.Realm;
import com.mercer.cpsg.swarm.oidc.OIDCPrincipal;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormData;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.server.session.Session;
import io.undertow.servlet.handlers.ServletRequestContext;
import io.undertow.servlet.spec.HttpSessionImpl;
import io.undertow.util.AttachmentKey;
import io.undertow.util.Headers;
import io.undertow.util.Methods;
import io.undertow.util.RedirectBuilder;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

/**
 * SpnegoHandler
 */
// inspired by ServletFormAuthenticationMechanism.java and
// http://connect2id.com/products/nimbus-oauth-openid-connect-sdk/guides/java-cookbook-for-openid-connect-public-clients
public class OIDCAuthenticationMechanism implements AuthenticationMechanism {

	private static final Logger LOG = Logger.getLogger(OIDCAuthenticationMechanism.class.getName());

	private static final String NONCE_KEY = "com.mercer.cpsg.swarm.oidc.auth.nonce";
	private static final String LOCATION_KEY = "com.mercer.cpsg.swarm.oidc.auth.location";

	private final String mechanismName;
	private final OIDCIdentityProvider oidcProvider;
	private final String redirectPath;
	private final FormParserFactory formParserFactory;
	private final IdentityManager identityManager;
	private final SecretKey stateKey;

	private OIDCAuthenticationMechanism(String mechanismName, Realm realm, String redirectPath, FormParserFactory formParserFactory, IdentityManager identityManager) {
		this.mechanismName = mechanismName;
		this.redirectPath = redirectPath;
		this.formParserFactory = formParserFactory;
		this.identityManager = identityManager;
		this.oidcProvider = configure(realm.getProvider());
		this.stateKey = stateKey();

	}

	@Override
	public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

		// ServletRequestContext servletRequestContext =
		// exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
		// HttpServletRequest request =
		// servletRequestContext.getOriginalRequest();
		// HttpServletResponse response =
		// servletRequestContext.getOriginalResponse();
		OIDCContext context = new OIDCContext();
		context.setError(false);
		exchange.putAttachment(OIDCContext.ATTACHMENT_KEY, context);

		LOG.fine("Requested URL: " + exchange.getRelativePath());

		// String authorization =
		// exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);

		if (exchange.getRequestPath().equals(redirectPath)) {
			return processOIDCAuthResponse(exchange);
		}

		return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;

	}

	@Override
	public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
		OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
		// even though authenticate() returns not attempted which should move on
		// to the next mechanism a challenge is still sent so check for errors
		// here and send appropriate response
		if (oidcContext.isError()) {
			return new ChallengeResult(false, HttpServletResponse.SC_UNAUTHORIZED);
		}

		String redirectURL = buildAuthorizationURL(exchange);
		LOG.fine("Challenge redirect:" + redirectURL);
		exchange.getResponseHeaders().put(Headers.LOCATION, redirectURL);
		return new ChallengeResult(true, HttpServletResponse.SC_FOUND);
	}

	protected AuthenticationMechanismOutcome processOIDCAuthResponse(HttpServerExchange exchange) {
		try {
			// check for IDP initiated sign on request
			if (exchange.getRequestMethod().equals(Methods.GET)) {
				if (exchange.getQueryParameters().containsKey("iss")) {
					// Since there is only one IDP configured automatically
					// redirect to it, no need to check which one
					return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;

				}
			}

			AuthenticationResponse authResp = authenticate(exchange);

			if (authResp instanceof AuthenticationErrorResponse) {
				ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
				throw new IllegalStateException(String.format("OIDC Authentication error: code %s description: %s", error.getCode(), error.getDescription()));
			}

			AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

			// could store returnURL/state
			// in session but state is encrypted
			State state = successResponse.getState();
			String returnURL = restoreState(state != null ? state.getValue() : null, exchange);

			AuthorizationCode authCode = successResponse.getAuthorizationCode();
			JWT idToken = successResponse.getIDToken();

			if (idToken == null && authCode != null) {
				OIDCTokenResponse tokenResponse = fetchToken(authCode, exchange);
				idToken = tokenResponse.getOIDCTokens().getIDToken();
			}
			validateToken(idToken, exchange);
			return complete(idToken, returnURL, exchange);

		} catch (Exception e) {
			LOG.log(Level.SEVERE, "", e);
			OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
			oidcContext.setError(true);
			exchange.getSecurityContext().authenticationFailed("OIDC auth response processing failed", mechanismName);
			return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
		}

	}

	protected AuthenticationResponse authenticate(HttpServerExchange exchange) throws Exception {
		Map<String, String> params = new HashMap<>();
		exchange.getQueryParameters().forEach((k, v) -> {
			params.put(k, v.getFirst());
		});
		if (exchange.getRequestMethod().equals(Methods.POST)) {
			FormData formData = formParserFactory.createParser(exchange).parseBlocking();
			formData.forEach(p -> {
				params.put(p, formData.getFirst(p).getValue());
			});
		}
		return AuthenticationResponseParser.parse(new URI(exchange.getRequestURI()), params);
	}

	protected void validateToken(JWT token, HttpServerExchange exchange) throws BadJOSEException, JOSEException {
		if (token == null) {
			throw new BadJOSEException("Token is null");
		} else if (token instanceof SignedJWT) {
			SignedJWT sToken = (SignedJWT) token;
			Nonce nonce;
			if (oidcProvider.isCheckNonce()) {
				nonce = new Nonce((String) getSession(exchange).getAttribute(NONCE_KEY));
			} else {
				nonce = null;
			}
			JWSAlgorithm jwsAlgorithm = sToken.getHeader().getAlgorithm();
			IDTokenValidator idTokenValidator = null;
			if (JWSAlgorithm.Family.RSA.contains(jwsAlgorithm)) {
				idTokenValidator = oidcProvider.getRsaValidator();
			} else if (JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm)) {
				idTokenValidator = oidcProvider.getHmacValidator();
			}
			idTokenValidator.validate(sToken, nonce);
		} else {
			throw new BadJOSEException("JWT signature requred on token");
		}
	}

	protected OIDCTokenResponse fetchToken(AuthorizationCode authCode, HttpServerExchange exchange) throws Exception {
		URI redirectURI = new URI(RedirectBuilder.redirect(exchange, redirectPath));
		TokenRequest tokenReq = new TokenRequest(oidcProvider.getTokenURI(), oidcProvider.getClientId(), new AuthorizationCodeGrant(authCode, redirectURI));
		HTTPResponse tokenHTTPResp = tokenReq.toHTTPRequest().send();
		TokenResponse tokenResponse = OIDCTokenResponseParser.parse(tokenHTTPResp);
		if (tokenResponse instanceof TokenErrorResponse) {
			ErrorObject error = ((TokenErrorResponse) tokenResponse).getErrorObject();
			throw new IllegalStateException(String.format("OIDC TokenRequest error: code %s description: %s", error.getCode(), error.getDescription()));
		}
		return (OIDCTokenResponse) tokenResponse;
	}

	protected UserInfoSuccessResponse fetchProfile(BearerAccessToken accessToken, HttpServerExchange exchange) throws Exception {
		UserInfoRequest userInfoReq = new UserInfoRequest(oidcProvider.getUserInfoURI(), accessToken);
		HTTPResponse userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
		UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		if (userInfoResponse instanceof UserInfoErrorResponse) {
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			throw new IllegalStateException(String.format("OIDC UserInfoRequest error: code %s description: %s", error.getCode(), error.getDescription()));
		}
		return (UserInfoSuccessResponse) userInfoResponse;
	}

	protected AuthenticationMechanismOutcome complete(JWT idToken, String returnURL, HttpServerExchange exchange) throws Exception {
		OIDCPrincipal principal = new OIDCPrincipal(idToken.getJWTClaimsSet().getSubject(), idToken.getJWTClaimsSet().getClaims());
		Account account = new AccountImpl(principal);
		account = identityManager.verify(account);
		if (account == null) {
			LOG.warning(String.format("OIDC subject %s not found in identity manager", principal.getName()));
			exchange.getSecurityContext().authenticationFailed("OIDC subject not found in identity manager", mechanismName);
			OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
			oidcContext.setError(true);
			return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
		}
		exchange.getSecurityContext().authenticationComplete(account, mechanismName, true);
		exchange.getResponseHeaders().put(Headers.LOCATION, returnURL != null && !returnURL.isEmpty() ? returnURL : "/");
		exchange.setStatusCode(HttpServletResponse.SC_FOUND);
		exchange.endExchange();
		LOG.fine("authentificated " + principal);
		return AuthenticationMechanismOutcome.AUTHENTICATED;
	}

	private String buildAuthorizationURL(HttpServerExchange exchange) {
		try {
			ClientID clientId = new ClientID(oidcProvider.getClientId());
			ResponseType responseType = new ResponseType(oidcProvider.getResponseType());
			ResponseMode responseMode = ResponseMode.FORM_POST;
			Prompt prompt = new Prompt(Prompt.Type.LOGIN);
			Display display = Display.PAGE;
			Scope scope = Scope.parse(oidcProvider.getScope());
			String redirectURL = RedirectBuilder.redirect(exchange, redirectPath, false);
			URI redirectURI = new URI(redirectURL);
			String returnURL = null;
			if (!exchange.getRequestPath().equals(redirectPath)) {
				returnURL = RedirectBuilder.redirect(exchange, exchange.getRelativePath());
			} else {
				returnURL = RedirectBuilder.redirect(exchange, "/", false);
			}
			String stateValue = persistState(returnURL, exchange);
			State state = stateValue != null ? new State(stateValue) : null;
			Nonce nonce = new Nonce();
			if (oidcProvider.isCheckNonce()) {
				getSession(exchange).setAttribute(NONCE_KEY, nonce.getValue());
			}
			AuthenticationRequest authRequest = new AuthenticationRequest(oidcProvider.getAuthURI(), responseType, responseMode, scope, clientId, redirectURI, state, nonce, display, prompt, -1, null, null, null, null, null, oidcProvider.getClaims(), null, null, null, null);
			return authRequest.toURI().toString();
		} catch (Exception e) {
			LOG.log(Level.SEVERE, "", e);
			return null;
		}

	}

	protected String persistState(String state, HttpServerExchange exchange) throws Exception {
		// if NoOnce is checked based on session value restore redirect URL the
		// same way
		if (oidcProvider.isCheckNonce()) {
			getSession(exchange).setAttribute(LOCATION_KEY, state);
			return state;
		} else {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, stateKey);
			byte[] secureReturnURL = cipher.doFinal(state.getBytes());
			return Base64.getEncoder().encodeToString(secureReturnURL);
		}
	}

	protected String restoreState(String state, HttpServerExchange exchange) throws Exception {
		if (oidcProvider.isCheckNonce()) {
			String previousState = (String) getSession(exchange).getAttribute(LOCATION_KEY);
			return previousState != null && previousState.equals(state) ? state : null;
		} else {
			byte[] secureReturnURL = Base64.getDecoder().decode(state);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, stateKey);
			try {
				secureReturnURL = cipher.doFinal(secureReturnURL);
				return new String(secureReturnURL);
			} catch (Exception e) {
				// non-critical exception
				LOG.log(Level.FINER, "State decryption failed", e);
				return null;
			}
		}
	}

	protected SecretKey stateKey() {
		// only generate the state encrpytion key if the HTTP session is going
		// to be used for nonance checking as well.
		if (!oidcProvider.isCheckNonce()) {
			try {
				if (oidcProvider.getClientSecret() != null && !oidcProvider.getClientSecret().isEmpty()) {
					byte[] key = oidcProvider.getClientSecret().getBytes("UTF-8");
					MessageDigest sha = MessageDigest.getInstance("SHA-1");
					key = sha.digest(key);
					key = Arrays.copyOf(key, 16);
					SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
					return secretKeySpec;
				} else {
					KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
					keyGenerator.init(128);
					return keyGenerator.generateKey();
				}

			} catch (Exception e) {
				LOG.log(Level.SEVERE, "", e);
				return null;
			}
		}
		return null;

	}

	protected Session getSession(HttpServerExchange exchange) {
		final ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
		HttpSessionImpl httpSession = servletRequestContext.getCurrentServletContext().getSession(exchange, true);
		Session session;
		if (System.getSecurityManager() == null) {
			session = httpSession.getSession();
		} else {
			session = AccessController.doPrivileged(new HttpSessionImpl.UnwrapSessionAction(httpSession));
		}
		return session;
	}

	protected OIDCIdentityProvider configure(IdentityProvider idp) {
		try {
			Secret secret = null;
			if (idp.getClientSecret() != null && !idp.getClientSecret().isEmpty()) {
				secret = new Secret(idp.getClientSecret());
			}
			ClientID clientId = new ClientID(idp.getClientId());
			Issuer issuer = null;
			URI authURI = null;
			URI tokenURI = null;
			URI userInfoURI = null;
			JWKSet rsaKeys = null;
			if (idp.getMetadataURL() != null && !idp.getMetadataURL().isEmpty()) {
				LOG.info(String.format("Loading OIDC Provider from metadata %s", idp.getName()));
				URL providerConfigurationURL = new URL(idp.getMetadataURL());
				OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.parse(IOUtils.toString(providerConfigurationURL.openStream()));
				issuer = new Issuer(providerMetadata.getIssuer());
				authURI = providerMetadata.getAuthorizationEndpointURI();
				tokenURI = providerMetadata.getTokenEndpointURI();
				userInfoURI = providerMetadata.getUserInfoEndpointURI();
				rsaKeys = getProviderRSAKeys(providerMetadata.getJWKSetURI());
			} else {
				LOG.info(String.format("Loading OIDC Provider %s", idp.getName()));
				issuer = new Issuer(idp.getIssuer());
				authURI = new URI(idp.getAuthURL());
				tokenURI = new URI(idp.getTokenURL());
				userInfoURI = new URI(idp.getUserInfoURL());
				rsaKeys = getProviderRSAKeys(idp.getJwsRSAKeys());
			}
			// expected algorithm, can move to OIDC later if needed
			IDTokenValidator rsaTokenValidator = new IDTokenValidator(issuer, clientId, JWSAlgorithm.RS256, rsaKeys);
			rsaTokenValidator.setMaxClockSkew(idp.getClockSkew());
			IDTokenValidator hmacTokenValidator = new IDTokenValidator(issuer, clientId, JWSAlgorithm.HS256, secret != null ? secret : new Secret());
			hmacTokenValidator.setMaxClockSkew(idp.getClockSkew());
			return new OIDCIdentityProvider(idp, issuer, authURI, tokenURI, userInfoURI, rsaTokenValidator, hmacTokenValidator);

		} catch (Exception e) {
			LOG.log(Level.SEVERE, String.format("OIDC metadata loading failure for %s", idp.getName()), e);
			return null;
		}
	}

	private JWKSet getProviderRSAKeys(URI jwkSetURI) throws Exception {
		InputStream is = jwkSetURI.toURL().openStream();
		String jsonString = IOUtils.toString(is);
		return getProviderRSAKeys(JSONObjectUtils.parse(jsonString));

	}

	private JWKSet getProviderRSAKeys(String jsonString) throws Exception {
		return getProviderRSAKeys(JSONObjectUtils.parse(jsonString));

	}

	JWKSet getProviderRSAKeys(JSONObject json) throws ParseException {
		JSONArray keyList = (JSONArray) json.get("keys");
		List<JWK> rsaKeys = new LinkedList<>();
		for (Object key : keyList) {
			JSONObject k = (JSONObject) key;
			if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
				rsaKeys.add(RSAKey.parse(k));
			}
		}
		if (!rsaKeys.isEmpty()) {
			return new JWKSet(rsaKeys);
		}
		throw new IllegalArgumentException("No RSA keys found");
	}

	public static final class Factory implements AuthenticationMechanismFactory {

		private OIDC<?> oidc;
		private final IdentityManager identityManager;

		public Factory(OIDC<?> oidc, IdentityManager identityManager) {
			this.oidc = oidc;
			this.identityManager = identityManager;
		}

		@Override
		public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
			// <auth-method>BASIC?silent=true,FORM</auth-method>
			// "When adding the mechanism name to the LoginConfig structure it
			// is also possible to specify a property map."
			String realm = properties.get(REALM);
			// String contextPath = properties.get(CONTEXT_PATH);
			Optional<Realm> realmProviders = oidc.listRealms().stream().filter(r -> realm.equals(r.getName())).findFirst();

			if (realmProviders.isPresent()) {
				return new OIDCAuthenticationMechanism(mechanismName, realmProviders.get(), oidc.getContext(), formParserFactory, identityManager);
			} else {
				throw new RuntimeException(String.format("Unable to find realm configuration for %s", realm));
			}

		}
	}

	public static ClaimsRequest parseClaimsRequest(String claimsRequest) {
		if (claimsRequest != null) {
			try {
				return ClaimsRequest.parse(claimsRequest);
			} catch (Exception e) {
				LOG.log(Level.SEVERE, "claim request parse error", e);
			}
		}
		return null;
	}

	public static class OIDCIdentityProvider {
		private final Issuer issuer;
		private final ClientID clientId;
		private final String clientSecret;
		private final String scope;
		private final String responseType;
		private final int clockSkew;
		private final boolean checkNonce;
		private final ClaimsRequest claims;
		private final URI authURI;
		private final URI tokenURI;
		private final URI userInfoURI;
		private final IDTokenValidator rsaValidator;
		private final IDTokenValidator hmacValidator;

		public OIDCIdentityProvider(IdentityProvider provider, Issuer issuer, URI authURI, URI tokenURI, URI userInfoURI, IDTokenValidator rsaValidator, IDTokenValidator hmacValidator) {
			this.clientId = new ClientID(provider.getClientId());
			this.clientSecret = provider.getClientSecret();
			this.responseType = provider.getResponseType();
			this.scope = provider.getScope();
			this.clockSkew = provider.getClockSkew();
			this.checkNonce = provider.isCheckNonce();
			this.claims = parseClaimsRequest(provider.getClaims());
			this.issuer = issuer;
			this.authURI = authURI;
			this.tokenURI = tokenURI;
			this.userInfoURI = userInfoURI;
			this.rsaValidator = rsaValidator;
			this.hmacValidator = hmacValidator;
		}

		public Issuer getIssuer() {
			return issuer;
		}

		public ClientID getClientId() {
			return clientId;
		}

		public String getClientSecret() {
			return clientSecret;
		}

		public String getResponseType() {
			return responseType;
		}

		public String getScope() {
			return scope;
		}

		public int getClockSkew() {
			return clockSkew;
		}

		public boolean isCheckNonce() {
			return checkNonce;
		}

		public ClaimsRequest getClaims() {
			return claims;
		}

		public URI getAuthURI() {
			return authURI;
		}

		public URI getTokenURI() {
			return tokenURI;
		}

		public URI getUserInfoURI() {
			return userInfoURI;
		}

		public IDTokenValidator getRsaValidator() {
			return rsaValidator;
		}

		public IDTokenValidator getHmacValidator() {
			return hmacValidator;
		}

	}

	public static class OIDCContext {

		static final AttachmentKey<OIDCContext> ATTACHMENT_KEY = AttachmentKey.create(OIDCContext.class);

		private boolean error;

		public boolean isError() {
			return error;
		}

		public void setError(boolean error) {
			this.error = error;
		}

	}

}
