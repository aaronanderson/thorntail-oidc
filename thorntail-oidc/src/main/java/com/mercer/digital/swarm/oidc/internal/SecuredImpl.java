

package com.mercer.digital.swarm.oidc.internal;

import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.NamedAsset;
import org.jboss.shrinkwrap.impl.base.ArchiveBase;
import org.jboss.shrinkwrap.impl.base.AssignableBase;
import org.wildfly.swarm.spi.api.JARArchive;
import org.wildfly.swarm.undertow.descriptors.SecurityConstraint;
import org.wildfly.swarm.undertow.descriptors.WebXmlAsset;

import com.mercer.digital.swarm.oidc.Secured;

public class SecuredImpl extends AssignableBase<ArchiveBase<?>> implements Secured {

	/**
	 * Constructs a new instance using the underlying specified archive, which
	 * is required
	 *
	 * @param archive
	 */
	public SecuredImpl(ArchiveBase<?> archive) {
		super(archive);

		Node node = getArchive().as(JARArchive.class).get("WEB-INF/web.xml");
		if (node == null) {
			this.asset = new WebXmlAsset();
			getArchive().as(JARArchive.class).add(this.asset);
		} else {
			NamedAsset asset = (NamedAsset) node.getAsset();
			if (!(asset instanceof WebXmlAsset)) {
				this.asset = new WebXmlAsset(asset.openStream());
				getArchive().as(JARArchive.class).add(this.asset);
			} else {
				this.asset = (WebXmlAsset) asset;
			}
		}

		

		// Setup web.xml
		this.asset.setContextParam("resteasy.scan", "true");
		
	}

	@Override
	public SecurityConstraint protect() {
		return this.asset.protect();
	}

	@Override
	public SecurityConstraint protect(String urlPattern) {
		return this.asset.protect(urlPattern);
	}

	private WebXmlAsset asset;
}
