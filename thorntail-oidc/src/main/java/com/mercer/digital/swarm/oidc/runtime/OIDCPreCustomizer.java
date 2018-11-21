package com.mercer.digital.swarm.oidc.runtime;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.wildfly.swarm.config.security.Flag;
import org.wildfly.swarm.config.security.SecurityDomain;
import org.wildfly.swarm.config.security.security_domain.ClassicAuthentication;
import org.wildfly.swarm.config.security.security_domain.authentication.LoginModule;
import org.wildfly.swarm.security.SecurityFraction;
import org.wildfly.swarm.spi.api.Customizer;
import org.wildfly.swarm.spi.api.annotations.Configurable;
import org.wildfly.swarm.spi.runtime.annotations.Pre;

import com.mercer.digital.swarm.oidc.OIDCFraction;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONArray;

@Pre
@ApplicationScoped
public class OIDCPreCustomizer implements Customizer {
	private static final Logger LOG = Logger.getLogger(OIDCPreCustomizer.class.getName());

	@Configurable("mercer-digital-wd.oidc.providers")
	private List<Map<String, String>> providers;

	@Configurable("mercer-digital-wd.oidc.realm")
	private String realm;

	@Configurable("mercer-digital-wd.oidc.default.subject")
	private String defaultSubject;

	@Configurable("mercer-digital-wd.oidc.default.roles")
	private List<String> defaultRoles;

	@Inject
	SecurityFraction securityFraction;

	@Inject
	private OIDCFraction oidcFraction;

	public void customize() {

		if (!oidcFraction.isInhibitDefaultSecurityDomain()) {
			securityFraction.securityDomain(new SecurityDomain("oidc-domain").classicAuthentication(new ClassicAuthentication().loginModule(new LoginModule("OIDC").code("com.mercer.digital.swarm.oidc.deployment.OIDCLoginModule").flag(Flag.REQUIRED).moduleOptions(new HashMap<Object, Object>() {
				{
					put("roles-claim-name", "groups");
				}
			}))));
		}

		if ((oidcFraction.config() == null || oidcFraction.config().listRealms().isEmpty())) {
			oidcFraction.config(o -> o.realm(realm, r -> {
				if (defaultSubject != null) {
					JSONArray claimRoles = new JSONArray();
					claimRoles.addAll(defaultRoles);
					JWTClaimsSet defaultClaimSet = new JWTClaimsSet.Builder().subject(defaultSubject).claim("preferred_username", defaultSubject)
							// .expirationDate(new Date(1300819380 * 1000l)
							.claim("groups", claimRoles).build();
					r.defaultClaimSet(defaultClaimSet);
				} else {
					for (Map<String, String> provider : providers) {
						r.provider(provider.get("name"), idp -> {
							idp.setScope(provider.getOrDefault("scope", "openid profile groups"));
							idp.setClientId(provider.get("clientId"));
							idp.setClientSecret(provider.get("clientSecret"));
							idp.setMetadataURL(provider.get("metadataURL"));
						});

					}
				}
			}));
		}

	}
}
