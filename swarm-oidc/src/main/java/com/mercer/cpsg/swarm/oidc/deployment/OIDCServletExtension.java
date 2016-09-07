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

import java.util.logging.Logger;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.CDI;
import javax.servlet.ServletContext;

import com.mercer.cpsg.swarm.oidc.OIDC;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.DeploymentInfo;

public class OIDCServletExtension implements ServletExtension {
	private static final Logger LOG = Logger.getLogger(OIDCServletExtension.class.getName());

	@Override
	public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
		BeanManager bm = CDI.current().getBeanManager();
		Bean<OIDC> bean = (Bean<OIDC>) bm.getBeans(OIDC.class).iterator().next();
		CreationalContext<OIDC> ctx = bm.createCreationalContext(bean);
		OIDC oidcConfig = (OIDC) bm.getReference(bean, OIDC.class, ctx);
		
		LOG.info("Registering OIDC authentication mechanism");
		deploymentInfo.addAuthenticationMechanism("OIDC", new OIDCAuthenticationMechanism.Factory(oidcConfig, deploymentInfo.getIdentityManager()));

	}

}