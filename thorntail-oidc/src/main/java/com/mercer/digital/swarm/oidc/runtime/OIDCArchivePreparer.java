

package com.mercer.digital.swarm.oidc.runtime;

import java.util.logging.Logger;

import javax.inject.Inject;

import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.wildfly.swarm.spi.api.DeploymentProcessor;
import org.wildfly.swarm.spi.api.JARArchive;
import org.wildfly.swarm.spi.runtime.annotations.DeploymentScoped;
import org.wildfly.swarm.undertow.UndertowFraction;
import org.wildfly.swarm.undertow.WARArchive;
import org.wildfly.swarm.undertow.descriptors.WebXmlAsset;

import com.mercer.digital.swarm.oidc.OIDC;
import com.mercer.digital.swarm.oidc.OIDCFraction;
import com.mercer.digital.swarm.oidc.deployment.OIDCPrincipal;

import io.undertow.Undertow;

@DeploymentScoped
public class OIDCArchivePreparer implements DeploymentProcessor {

	private static final Logger LOG = Logger.getLogger(OIDCArchivePreparer.class.getName());

	@Inject
	OIDCFraction oidcFraction;
	
	@Inject
	UndertowFraction undertowFraction;
	
	Archive archive;
	
	 @Inject
	    public OIDCArchivePreparer(Archive archive) {
	        this.archive = archive;
	    }

	@Override
	public void process() throws Exception {
		if (oidcFraction.config() != null && !oidcFraction.config().listRealms().isEmpty()) {

			WebXmlAsset webXML = null;
			Node node = this.archive.as(JARArchive.class).get("WEB-INF/web.xml");
			if (node == null) {
				webXML = new WebXmlAsset();
				this.archive.as(JARArchive.class).add(webXML);
			} else {
				Asset asset = node.getAsset();
				if (!(asset instanceof WebXmlAsset)) {
					webXML = new WebXmlAsset(asset.openStream());
					this.archive.as(JARArchive.class).add(webXML);
				} else {
					webXML = (WebXmlAsset) asset;
				}
			}
			if (webXML.getLoginRealm("OIDC") == null) {
				webXML.setLoginConfig("OIDC", oidcFraction.config().listRealms().get(0).getName());
			}
			
			/*if (fraction.isRemoveAllSecurityConstraints()) {
				webXML.allConstraints().clear();
			}*/
						
			JARArchive jar = this.archive.as(JARArchive.class);
			jar.addModule("com.mercer.digital.swarm.oidc", "deployment");
			jar.addClass(OIDC.class);
			jar.addAsServiceProvider("io.undertow.servlet.ServletExtension", "com.mercer.digital.swarm.oidc.deployment.OIDCServletExtension");
			
			//jar.addModule("com.mercer.cpsg.swarm.oidc", "runtime");
			//jar.addModule("com.mercer.cpsg.swarm.oidc", "api");// This was needed so that whren swarm is started with IDE/mvn wildfly-swarm:run picks up the OIDCPrincipal class

			if (!oidcFraction.isInhibitDefaultSecurityDomain()) {
				this.archive.as(WARArchive.class).setSecurityDomain("oidc-domain");
			}
		}

		/* webXML.setLoginConfig("OIDC", "test"); */
		// added runtime ServletExtension to deployment classpath and declare
		// extension

	}

}
