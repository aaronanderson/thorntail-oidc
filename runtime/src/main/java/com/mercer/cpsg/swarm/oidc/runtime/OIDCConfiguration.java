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

import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.jboss.dmr.ModelNode;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.wildfly.swarm.spi.api.JARArchive;
import org.wildfly.swarm.spi.runtime.AbstractServerConfiguration;
import org.wildfly.swarm.undertow.WARArchive;
import org.wildfly.swarm.undertow.descriptors.WebXmlAsset;

import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.mercer.cpsg.swarm.oidc.OIDCFraction;

public class OIDCConfiguration extends AbstractServerConfiguration<OIDCFraction> {

	private static final Logger LOG = Logger.getLogger(OIDCConfiguration.class.getName());
	// Not ideal but the OIDC fraction configuration needs to be serialized and
	// prepareArchive does not have access to it
	OIDCFraction fraction;

	public OIDCConfiguration() {
		super(OIDCFraction.class);

	}

	@Override
	public OIDCFraction defaultFraction() {
		return new OIDCFraction();
	}

	@Override
	public void prepareArchive(Archive<?> a) {
		if (!fraction.listRealms().isEmpty()) {
			ObjectMapper mapper = new ObjectMapper();
			mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
			mapper.setVisibility(PropertyAccessor.ALL, Visibility.NONE);
			mapper.setVisibility(PropertyAccessor.FIELD, Visibility.ANY);
			mapper.enable(SerializationFeature.INDENT_OUTPUT);
			mapper.addMixIn(OIDCFraction.class, OIDCFractionMixIn.class);

			try {
				// overwrite if it exists rather than merge
				Asset oidcJson = new ByteArrayAsset(mapper.writeValueAsString(fraction).getBytes());
				a.as(WARArchive.class).addAsWebInfResource(oidcJson, "oidc.json");
			} catch (Exception e) {
				LOG.log(Level.SEVERE, "", e);
			}

			WebXmlAsset webXML = null;
			Node node = a.as(JARArchive.class).get("WEB-INF/web.xml");
			if (node == null) {
				webXML = new WebXmlAsset();
				a.as(JARArchive.class).add(webXML);
			} else {
				Asset asset = node.getAsset();
				if (!(asset instanceof WebXmlAsset)) {
					webXML = new WebXmlAsset(asset.openStream());
					a.as(JARArchive.class).add(webXML);
				} else {
					webXML = (WebXmlAsset) asset;
				}
			}
			if (webXML.getLoginRealm("OIDC") == null && !fraction.listRealms().isEmpty()) {
				webXML.setLoginConfig("OIDC", fraction.listRealms().get(0).getName());
			}
			
			a.as(JARArchive.class).addModule("com.mercer.cpsg.swarm.oidc", "runtime");
			a.as(JARArchive.class).addModule("com.mercer.cpsg.swarm.oidc", "api");//This was needed so that whren swarm is started with IDE/mvn wildfly-swarm:run picks up the OIDCPrincipal class
			a.as(JARArchive.class).addAsServiceProvider("io.undertow.servlet.ServletExtension", "com.mercer.cpsg.swarm.oidc.runtime.OIDCServletExtension");
			
			if (!fraction.isInhibitDefaultDatasource()) {
				a.as(WARArchive.class).setSecurityDomain("oidc-domain");
			}
		}

		
		/*
		
		
		webXML.setLoginConfig("OIDC", "test");
		*/
		// added runtime ServletExtension to deployment classpath and declare
		// extension

		
	}

	@Override
	public List<ModelNode> getList(OIDCFraction fraction) {
		this.fraction = fraction;
		return Collections.emptyList();

	}

	public static abstract class OIDCFractionMixIn {
		@JsonIgnore
		private boolean inhibitDefaultDatasource;
		@JsonRawValue
		private String jwsRSAKeys;
		@JsonRawValue
		private String claims;

	}
}
