package com.mercer.cpsg.swarm.oidc.runtime;

import java.util.HashMap;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.wildfly.swarm.config.security.Flag;
import org.wildfly.swarm.config.security.SecurityDomain;
import org.wildfly.swarm.config.security.security_domain.ClassicAuthentication;
import org.wildfly.swarm.config.security.security_domain.authentication.LoginModule;
import org.wildfly.swarm.security.SecurityFraction;
import org.wildfly.swarm.spi.api.Customizer;
import org.wildfly.swarm.spi.api.StageConfig;
import org.wildfly.swarm.spi.runtime.annotations.Pre;
import com.mercer.cpsg.swarm.oidc.OIDC;
import com.mercer.cpsg.swarm.oidc.OIDCFraction;

@Pre
@Singleton
public class OIDCPreCustomizer implements Customizer {
	private static final Logger LOG = Logger.getLogger(OIDCPreCustomizer.class.getName());

	@Inject
	StageConfig stageConfig;

	@Inject
	SecurityFraction securityFraction;

	@Inject
	private OIDCFraction oidcFraction;

	public void customize() {

		if (!oidcFraction.isInhibitDefaultSecurityDomain()) {
			securityFraction.securityDomain(new SecurityDomain("oidc-domain").classicAuthentication(new ClassicAuthentication().loginModule(new LoginModule("OIDC").code("com.mercer.cpsg.swarm.oidc.deployment.OIDCLoginModule").flag(Flag.REQUIRED).moduleOptions(new HashMap<Object, Object>() {
				{
					put("roles-claim-name", "groups");
				}
			}))));
		}

		if ((oidcFraction.config() == null || oidcFraction.config().listRealms().isEmpty())) {
			oidcFraction.config(o -> o.realm(stageConfig.resolve("swarm.oidc.realm").getValue(), r -> {
				r.provider("Okta", idp -> {
					idp.setScope("openid profile groups");
					idp.setClientId(stageConfig.resolve("swarm.oidc.clientId").getValue());
					idp.setMetadataURL(stageConfig.resolve("swarm.oidc.metadataURL").getValue());

				});
			}));
		}
		oidcFraction.setInstalledConfig(oidcFraction.config());

	}
}
