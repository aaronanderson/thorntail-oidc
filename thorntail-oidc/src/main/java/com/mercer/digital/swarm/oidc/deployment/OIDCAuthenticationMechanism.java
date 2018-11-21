
package com.mercer.digital.swarm.oidc.deployment;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.AccessController;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
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

import org.wildfly.extension.undertow.security.AccountImpl;

import com.mercer.digital.swarm.oidc.OIDC;
import com.mercer.digital.swarm.oidc.OIDC.IdentityProvider;
import com.mercer.digital.swarm.oidc.OIDC.Realm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
import com.nimbusds.oauth2.sdk.token.AccessToken;
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
import io.undertow.server.handlers.Cookie;
import io.undertow.server.handlers.CookieImpl;
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

// inspired by ServletFormAuthenticationMechanism.java and
// http://connect2id.com/products/nimbus-oauth-openid-connect-sdk/guides/java-cookbook-for-openid-connect-public-clients
public class OIDCAuthenticationMechanism implements AuthenticationMechanism {

	private static final Logger LOG = Logger.getLogger(OIDCAuthenticationMechanism.class.getName());

	private static final String NONCE_KEY = "com.mercer.digital.swarm.oidc.auth.nonce";
	private static final String LOCATION_KEY = "com.mercer.digital.swarm.oidc.auth.location";

	private static final String IDP_KEY = "idp";

	private final String mechanismName;
	private final JWTClaimsSet defaultClaimSet;
	private final List<OIDCIdentityProvider> oidcProviders;
	private final String redirectPath;
	private final FormParserFactory formParserFactory;
	private final IdentityManager identityManager;

	private OIDCAuthenticationMechanism(String mechanismName, Realm realm, String redirectPath, FormParserFactory formParserFactory, IdentityManager identityManager) {
		this.mechanismName = mechanismName;
		this.redirectPath = redirectPath;
		this.formParserFactory = formParserFactory;
		this.identityManager = identityManager;
		if (realm.getDefaultClaimSet() != null) {
			this.defaultClaimSet = realm.getDefaultClaimSet();
			this.oidcProviders = null;
		} else {
			this.defaultClaimSet = null;
			this.oidcProviders = configure(realm.listProviders());
		}
	}

	@Override
	public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

		// ServletRequestContext servletRequestContext
		// exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
		// HttpServletRequest request =
		// servletRequestContext.getOriginalRequest();
		// HttpServletResponse response =
		// servletRequestContext.getOriginalResponse();
		OIDCContext context = new OIDCContext();
		context.setError(false);
		exchange.putAttachment(OIDCContext.ATTACHMENT_KEY, context);

		LOG.fine("Requested URL: " + exchange.getRelativePath());

		// Only authenticate if required. For example, if no auth-constraint is specified
		// for a security-constraint in the web.xml unauthenticated access should be allowed.
		if (!securityContext.isAuthenticationRequired()) {
			return AuthenticationMechanismOutcome.AUTHENTICATED;
		}

		if (defaultClaimSet != null) {
			return processDefaultClaimSet(exchange);
		}

		if (exchange.getRequestHeaders().contains(Headers.AUTHORIZATION)) {
			return processAuthorization(exchange);
		}

		if (exchange.getRequestPath().equals(redirectPath)) {
			return processOIDCAuthResponse(exchange);
		}

		// for identity provider initiated login, capture the issuer. If IDP
		// pointed at OIDC endpoint above authenticated users would bypass this
		// module
		// and the request would go to the protected application. More than
		// likely the application would not have
		// anything mapped at the OIDC endpoint URL and an error would be
		// generated.
		if (exchange.getQueryParameters().containsKey("iss")) {
			context.setIssuer(exchange.getQueryParameters().get("iss").getLast());
		}

		return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;

	}

	@Override
	public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
		OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
		// NOT_AUTHENTICATED and NOT_ATTEMPTED always send challenges
		if (oidcContext.isError()) {
			return new ChallengeResult(false, HttpServletResponse.SC_UNAUTHORIZED);
		}

		String redirectURL = buildAuthorizationURL(exchange);
		LOG.fine("Challenge redirect:" + redirectURL);
		exchange.getResponseHeaders().put(Headers.LOCATION, redirectURL);
		return new ChallengeResult(true, HttpServletResponse.SC_FOUND);
	}

	protected AuthenticationMechanismOutcome processDefaultClaimSet(HttpServerExchange exchange) {
		try {
			return complete(defaultClaimSet, null, null, exchange, false);
		} catch (Exception e) {
			OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
			oidcContext.setError(true);
			exchange.getSecurityContext().authenticationFailed("Unable to authenticate using the default claimset", mechanismName);
			return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
		}

	}

	protected AuthenticationMechanismOutcome processAuthorization(HttpServerExchange exchange) {
		String authorization = exchange.getRequestHeaders().getFirst(Headers.AUTHORIZATION);
		try {
			//if access token is JWT, as is the case with Okta, try to glean identity provider. Otherwise use cookie preference. If nothing else use first IDP.
			BearerAccessToken accessToken = BearerAccessToken.parse(authorization);
			Cookie cookieRequestedIDP = Optional.ofNullable(exchange.getRequestCookies().get(IDP_KEY)).orElse(null);
			OIDCIdentityProvider oidcProvider = restoreOIDCProvider(accessToken, cookieRequestedIDP);
			UserInfoSuccessResponse info = fetchProfile(accessToken, oidcProvider);
			// JWT idToken = JWTParser.parse(accessToken.getValue());
			// JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("demo").build();
			// PlainJWT idToken = new PlainJWT(claimsSet);
			// validateToken(idToken, exchange, false);
			return complete(info.getUserInfo().toJWTClaimsSet(), accessToken, null, exchange, false);
		} catch (Exception e) {
			OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
			oidcContext.setError(true);
			exchange.getSecurityContext().authenticationFailed("Unable to obtain OIDC JWT token from authorization header", mechanismName);
			return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
		}

	}

	protected AuthenticationMechanismOutcome processOIDCAuthResponse(HttpServerExchange exchange) {
		try {
			Cookie cookieRequestedIDP = Optional.ofNullable(exchange.getRequestCookies().get(IDP_KEY)).orElse(null);
			AuthenticationResponse authResp = authenticate(exchange);

			if (authResp instanceof AuthenticationErrorResponse) {
				ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
				throw new IllegalStateException(String.format("OIDC Authentication error: code %s description: %s", error.getCode(), error.getDescription()));
			}

			AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;

			// could store returnURL/state
			// in session but state is encrypted
			State state = successResponse.getState();

			AuthorizationCode authCode = successResponse.getAuthorizationCode();
			JWT idToken = successResponse.getIDToken();
			AccessToken accessToken = successResponse.getAccessToken();

			OIDCIdentityProvider oidcProvider = null;
			if (idToken != null) {
				for (OIDCIdentityProvider candidateProvider : oidcProviders) {
					if (candidateProvider.getIssuer().getValue().equals(idToken.getJWTClaimsSet().getIssuer())) {
						oidcProvider = candidateProvider;
						break;
					}
				}

			}
			if (oidcProvider == null) {
				oidcProvider = restoreOIDCProvider(cookieRequestedIDP);
			}

			if (idToken == null && authCode != null) {
				OIDCTokenResponse tokenResponse = fetchToken(authCode, exchange, oidcProvider);
				idToken = tokenResponse.getOIDCTokens().getIDToken();
				accessToken = tokenResponse.getOIDCTokens().getAccessToken();
			}
			validateToken(idToken, exchange, true, oidcProvider);
			if (cookieRequestedIDP == null || !cookieRequestedIDP.equals(oidcProvider.getName())) {
				setIDPCookie(exchange, oidcProvider.getName());
			}
			String returnURL = restoreState(state != null ? state.getValue() : null, exchange, oidcProvider);

			return complete(idToken.getJWTClaimsSet(), accessToken, returnURL, exchange, true);

		} catch (Exception e) {
			LOG.log(Level.SEVERE, "", e);
			OIDCContext oidcContext = exchange.getAttachment(OIDCContext.ATTACHMENT_KEY);
			oidcContext.setError(true);
			exchange.getSecurityContext().authenticationFailed("OIDC auth response processing failed", mechanismName);
			return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
		}

	}

	private OIDCIdentityProvider restoreOIDCProvider(Cookie cookieRequestedIDP) {
		OIDCIdentityProvider oidcProvider = null;
		if (cookieRequestedIDP != null) {
			for (OIDCIdentityProvider candidateProvider : oidcProviders) {
				if (cookieRequestedIDP.getValue().equals(candidateProvider.getName())) {
					oidcProvider = candidateProvider;
					break;
				}
			}
		}
		if (oidcProvider == null) {
			oidcProvider = oidcProviders.get(0);
		}
		return oidcProvider;
	}

	private OIDCIdentityProvider restoreOIDCProvider(BearerAccessToken accessToken, Cookie cookieRequestedIDP) {
		OIDCIdentityProvider oidcProvider = null;
		if (accessToken != null) {
			try {
				SignedJWT accessTokenJWT = SignedJWT.parse(accessToken.getValue());
				String issuer = accessTokenJWT.getJWTClaimsSet().getIssuer();
				for (OIDCIdentityProvider candidateProvider : oidcProviders) {
					if (issuer.equals(candidateProvider.getIssuer().getValue())) {
						oidcProvider = candidateProvider;
						break;
					}
				}
			} catch (ParseException e) {
			}
		}
		if (oidcProvider == null) {
			oidcProvider = restoreOIDCProvider(cookieRequestedIDP);
		}
		return oidcProvider;
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

	protected void validateToken(JWT token, HttpServerExchange exchange, boolean checkNonce, OIDCIdentityProvider oidcProvider) throws BadJOSEException, JOSEException {
		if (token == null) {
			throw new BadJOSEException("Token is null");
		} else if (token instanceof SignedJWT) {
			SignedJWT sToken = (SignedJWT) token;
			Nonce nonce;
			if (checkNonce && oidcProvider.isCheckNonce()) {
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
			if (idTokenValidator == null) {
				throw new BadJOSEException(String.format("JWT validator unavailable for %s", jwsAlgorithm.getName()));
			}
			idTokenValidator.validate(sToken, nonce);
		} else {
			throw new BadJOSEException("JWT signature requred on token");
		}
	}

	protected OIDCTokenResponse fetchToken(AuthorizationCode authCode, HttpServerExchange exchange, OIDCIdentityProvider oidcProvider) throws Exception {
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

	protected UserInfoSuccessResponse fetchProfile(BearerAccessToken accessToken, OIDCIdentityProvider oidcProvider) throws Exception {
		UserInfoRequest userInfoReq = new UserInfoRequest(oidcProvider.getUserInfoURI(), accessToken);
		HTTPResponse userInfoHTTPResp = userInfoReq.toHTTPRequest().send();
		UserInfoResponse userInfoResponse = UserInfoResponse.parse(userInfoHTTPResp);
		if (userInfoResponse instanceof UserInfoErrorResponse) {
			ErrorObject error = ((UserInfoErrorResponse) userInfoResponse).getErrorObject();
			throw new IllegalStateException(String.format("OIDC UserInfoRequest error: code %s description: %s", error.getCode(), error.getDescription()));
		}
		return (UserInfoSuccessResponse) userInfoResponse;
	}

	protected AuthenticationMechanismOutcome complete(JWTClaimsSet claims, AccessToken accessToken, String returnURL, HttpServerExchange exchange, boolean redirect) throws Exception {
		OIDCPrincipal principal = new OIDCPrincipalExt(claims, accessToken);
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
		if (redirect) {
			exchange.getResponseHeaders().put(Headers.LOCATION, returnURL != null && !returnURL.isEmpty() ? returnURL : "/");
			exchange.setStatusCode(HttpServletResponse.SC_FOUND);
			exchange.endExchange();
		}
		LOG.fine("authentificated " + principal);
		return AuthenticationMechanismOutcome.AUTHENTICATED;
	}

	private String buildAuthorizationURL(HttpServerExchange exchange) {
		OIDCIdentityProvider oidcProvider = selectOIDCProvider(exchange);
		try {
			ClientID clientId = new ClientID(oidcProvider.getClientId());
			ResponseType responseType = new ResponseType(oidcProvider.getResponseType());
			ResponseMode responseMode = ResponseMode.FORM_POST;
			Prompt prompt = new Prompt(Prompt.Type.LOGIN);
			Display display = Display.PAGE;
			Scope scope = Scope.parse(oidcProvider.getScope());

			//if proxy scheme needs to be preserved, i.e. TLS terminator is used and WildFly receives http requests, use the have the proxy set the host and X-Forwarded-Proto header and use the  
			//swarm:undertow:servers:default-server:http-listeners:default:proxy-address-forwarding: true setting to allow WildFly to write the correct scheme  
			String redirectURL = RedirectBuilder.redirect(exchange, redirectPath, false);
			URI redirectURI = new URI(redirectURL);
			String returnURL = null;
			if (!exchange.getRequestPath().equals(redirectPath)) {
				returnURL = RedirectBuilder.redirect(exchange, exchange.getRelativePath());
			} else {
				returnURL = RedirectBuilder.redirect(exchange, "/", false);
			}

			String stateValue = persistState(returnURL, exchange, oidcProvider);
			State state = stateValue != null ? new State(stateValue) : new State();
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

	private OIDCIdentityProvider selectOIDCProvider(HttpServerExchange exchange) {
		String requestedIDP = null;
		Cookie cookieRequestedIDP = exchange.getRequestCookies().get(IDP_KEY);
		//check for IDP parameter
		Deque<String> queryRequestedIDP = exchange.getQueryParameters().get(IDP_KEY);
		if (queryRequestedIDP != null) {
			cookieRequestedIDP = null;
			requestedIDP = queryRequestedIDP.getFirst();
		} else {
			//check for IDP cookie
			if (cookieRequestedIDP != null) {
				requestedIDP = cookieRequestedIDP.getValue();
			}
		}
		OIDCIdentityProvider oidcProvider = null;
		if (requestedIDP != null) {
			for (OIDCIdentityProvider canidateProvider : oidcProviders) {
				if (requestedIDP.equals(canidateProvider.getName())) {
					oidcProvider = canidateProvider;
					break;
				}
			}
		}
		if (oidcProvider == null) {
			oidcProvider = oidcProviders.get(0);
		} else if (cookieRequestedIDP == null) {
			setIDPCookie(exchange, oidcProvider.getName());
		}
		return oidcProvider;
	}

	protected void setIDPCookie(HttpServerExchange exchange, String idpName) {
		//needed for local testing
		String domain = exchange.getHostName();
		if ("localhost".equals(domain)) {
			domain = null;
		}
		boolean secure = "https".equals(exchange.getRequestScheme());
		exchange.getResponseCookies().put(IDP_KEY, new CookieImpl(IDP_KEY).setMaxAge(10 * 365 * 24 * 60 * 60).setHttpOnly(true).setSecure(secure).setDomain(domain).setPath("/").setValue(idpName));
	}

	protected String persistState(String state, HttpServerExchange exchange, OIDCIdentityProvider oidcProvider) throws Exception {
		// if NoOnce is checked based on session value restore redirect URL the
		// same way
		if (oidcProvider.isCheckNonce()) {
			getSession(exchange).setAttribute(LOCATION_KEY, state);
			return state;
		} else {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, oidcProvider.getStateKey());
			byte[] secureReturnURL = cipher.doFinal(state.getBytes());
			return Base64.getEncoder().encodeToString(secureReturnURL);
		}
	}

	protected String restoreState(String state, HttpServerExchange exchange, OIDCIdentityProvider oidcProvider) throws Exception {
		if (oidcProvider.isCheckNonce()) {
			String previousState = (String) getSession(exchange).getAttribute(LOCATION_KEY);
			return previousState != null && previousState.equals(state) ? state : null;
		} else {
			byte[] secureReturnURL = Base64.getDecoder().decode(state);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, oidcProvider.getStateKey());
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

	protected SecretKey stateKey(boolean isCheckNonce, String clientSecret) {
		// only generate the state encryption key if the HTTP session is going
		// to be used for nonance checking as well.
		if (!isCheckNonce) {
			try {
				if (clientSecret != null && !clientSecret.isEmpty()) {
					byte[] key = clientSecret.getBytes("UTF-8");
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

	protected List<OIDCIdentityProvider> configure(List<IdentityProvider> idps) {
		List<OIDCIdentityProvider> providers = new LinkedList<>();

		for (IdentityProvider idp : idps) {
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
					OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.parse(IOUtils.readInputStreamToString(providerConfigurationURL.openStream(), Charset.defaultCharset()));
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
				IDTokenValidator rsaTokenValidator = null;
				if (rsaKeys != null) {
					rsaTokenValidator = new IDTokenValidator(issuer, clientId, JWSAlgorithm.RS256, rsaKeys);
					rsaTokenValidator.setMaxClockSkew(idp.getClockSkew());
				}
				IDTokenValidator hmacTokenValidator = new IDTokenValidator(issuer, clientId, JWSAlgorithm.HS256, secret != null ? secret : new Secret());
				hmacTokenValidator.setMaxClockSkew(idp.getClockSkew());

				SecretKey stateKey = stateKey(idp.isCheckNonce(), idp.getClientSecret());

				providers.add(new OIDCIdentityProvider(idp, issuer, authURI, tokenURI, userInfoURI, rsaTokenValidator, hmacTokenValidator, stateKey));
			} catch (Exception e) {
				LOG.log(Level.SEVERE, String.format("OIDC metadata loading failure for %s", idp.getName()), e);
			}
		}

		return providers;
	}

	private JWKSet getProviderRSAKeys(URI jwkSetURI) throws Exception {
		try {
			InputStream is = jwkSetURI.toURL().openStream();
			String jsonString = IOUtils.readInputStreamToString(is, Charset.defaultCharset());
			return getProviderRSAKeys(JSONObjectUtils.parse(jsonString));
		} catch (Exception e) {
			return null;
		}

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

		private OIDC oidc;
		private final IdentityManager identityManager;

		public Factory(OIDC oidc, IdentityManager identityManager) {
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
		private final String name;
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
		private final SecretKey stateKey;

		public OIDCIdentityProvider(IdentityProvider provider, Issuer issuer, URI authURI, URI tokenURI, URI userInfoURI, IDTokenValidator rsaValidator, IDTokenValidator hmacValidator, SecretKey stateKey) {
			this.name = provider.getName();
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
			this.stateKey = stateKey;
		}

		public String getName() {
			return name;
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

		public SecretKey getStateKey() {
			return stateKey;
		}

	}

	public static class OIDCContext {

		static final AttachmentKey<OIDCContext> ATTACHMENT_KEY = AttachmentKey.create(OIDCContext.class);

		private boolean error;
		private String issuer;

		public boolean isError() {
			return error;
		}

		public void setError(boolean error) {
			this.error = error;
		}

		public String getIssuer() {
			return issuer;
		}

		public void setIssuer(String issuer) {
			this.issuer = issuer;
		}

	}

	public class OIDCPrincipalExt extends OIDCPrincipal {
		final JWTClaimsSet claimsSet;
		final AccessToken accessToken;

		protected OIDCPrincipalExt(JWTClaimsSet claimsSet, AccessToken accessToken) throws ParseException {
			super(claimsSet.getSubject(), claimsSet.getClaims());
			this.claimsSet = claimsSet;
			this.accessToken = accessToken;

		}

	}

}
