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
import java.util.logging.Logger;

import javax.servlet.ServletContext;import org.jboss.jandex.IndexWriter;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.mercer.cpsg.swarm.oidc.OIDC;

import io.undertow.servlet.ServletExtension;
import io.undertow.servlet.api.AuthMethodConfig;
import io.undertow.servlet.api.DeploymentInfo;

public class OIDCServletExtension implements ServletExtension {
	 private static final Logger LOG = Logger.getLogger(OIDCServletExtension.class.getName());
	// private static final BootstrapLogger LOG =
	// BootstrapLogger.logger(OIDCServletExtension.class.getName());

	@Override
	public void handleDeployment(DeploymentInfo deploymentInfo, ServletContext servletContext) {
		InputStream oidcJson = servletContext.getResourceAsStream("/WEB-INF/oidc.json");
		if (oidcJson != null) {
			ObjectMapper mapper = new ObjectMapper();
			mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
			mapper.setVisibility(PropertyAccessor.ALL, Visibility.NONE);
			mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
			mapper.enable(SerializationFeature.INDENT_OUTPUT);
			
			try {
				// overwrite if it exists rather than merge
				OIDC oidc = mapper.readValue(oidcJson, OIDC.class);
				LOG.info("Registering OIDC authentication mechanism");
				deploymentInfo.addAuthenticationMechanism("OIDC", new OIDCAuthenticationMechanism.Factory(oidc, deploymentInfo.getIdentityManager()));				
			} catch (Exception e) {
				e.printStackTrace();
				// LOG.error("", e);
			}
		} else {
			// LOG.error("WEB-INF/oidc.json unavailable.");
			System.err.println("WEB-INF/oidc.json unavailable.");
		}

	}
	
}