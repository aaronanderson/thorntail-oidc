

package com.mercer.digital.swarm.oidc.deployment;

import java.util.logging.Logger;

import javax.servlet.ServletContext;

import com.mercer.digital.swarm.oidc.OIDC;
import com.mercer.digital.swarm.oidc.OIDCFraction;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;

public class OIDCServletExtension implements ServletExtension {
	private static final Logger LOG = Logger.getLogger(OIDCServletExtension.class.getName());

	@Override
	public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
		OIDC oidcConfig = OIDC.getInstance();
		LOG.info("Registering OIDC authentication mechanism");
		deploymentInfo.addAuthenticationMechanism("OIDC", new OIDCAuthenticationMechanism.Factory(oidcConfig, deploymentInfo.getIdentityManager()));

	}

}
