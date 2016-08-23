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

import java.util.logging.Logger;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.wildfly.swarm.spi.api.ArchivePreparer;
import org.wildfly.swarm.spi.api.JARArchive;
import org.wildfly.swarm.undertow.WARArchive;
import org.wildfly.swarm.undertow.descriptors.WebXmlAsset;

import com.mercer.cpsg.swarm.oidc.OIDC;
import com.mercer.cpsg.swarm.oidc.OIDCFraction;
import com.mercer.cpsg.swarm.oidc.deployment.OIDCServletExtension;

@Singleton
public class OIDCArchivePreparer implements ArchivePreparer {

	private static final Logger LOG = Logger.getLogger(OIDCArchivePreparer.class.getName());

	@Inject
	OIDCFraction fraction;

	@Override
	public void prepareArchive(Archive<?> a) {
		if (fraction.config() != null && !fraction.config().listRealms().isEmpty()) {

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
			if (webXML.getLoginRealm("OIDC") == null) {
				webXML.setLoginConfig("OIDC", fraction.config().listRealms().get(0).getName());
			}
			JARArchive jar = a.as(JARArchive.class);
			jar.addModule("com.mercer.cpsg.swarm.oidc", "deployment");
			jar.addClass(OIDC.class);
			jar.addAsServiceProvider("io.undertow.servlet.ServletExtension", "com.mercer.cpsg.swarm.oidc.deployment.OIDCServletExtension");

			//jar.addModule("com.mercer.cpsg.swarm.oidc", "runtime");
			//jar.addModule("com.mercer.cpsg.swarm.oidc", "api");// This was needed so that whren swarm is started with IDE/mvn wildfly-swarm:run picks up the OIDCPrincipal class

			if (!fraction.isInhibitDefaultSecurityDomain()) {
				a.as(WARArchive.class).setSecurityDomain("oidc-domain");
			}
		}

		/* webXML.setLoginConfig("OIDC", "test"); */
		// added runtime ServletExtension to deployment classpath and declare
		// extension

	}

}
