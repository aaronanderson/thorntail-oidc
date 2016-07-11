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

package com.mercer.cpsg.swarm.oidc.internal;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.jboss.shrinkwrap.api.Node;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.jboss.shrinkwrap.api.asset.ByteArrayAsset;
import org.jboss.shrinkwrap.api.asset.NamedAsset;
import org.jboss.shrinkwrap.impl.base.ArchiveBase;
import org.jboss.shrinkwrap.impl.base.AssignableBase;
import org.jboss.shrinkwrap.impl.base.importer.zip.ZipImporterImpl;
import org.wildfly.swarm.bootstrap.util.BootstrapProperties;
import org.wildfly.swarm.spi.api.JARArchive;
import org.wildfly.swarm.undertow.descriptors.SecurityConstraint;
import org.wildfly.swarm.undertow.descriptors.WebXmlAsset;

import com.mercer.cpsg.swarm.oidc.OIDC;
import com.mercer.cpsg.swarm.oidc.Secured;

/**
 * @author Bob McWhirter
 * @author Ken Finnigan
 */
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

		InputStream oidcJson = Thread.currentThread().getContextClassLoader().getResourceAsStream("oidc.json");
		if (oidcJson == null) {

			String appArtifact = System.getProperty(BootstrapProperties.APP_ARTIFACT);

			if (appArtifact != null) {
				try (InputStream in = ClassLoader.getSystemClassLoader().getResourceAsStream("_bootstrap/" + appArtifact)) {
					ZipImporterImpl importer = new ZipImporterImpl(archive);
					importer.importFrom(in);
					Node jsonNode = archive.get("oidc.json");
					if (jsonNode == null) {
						jsonNode = archive.get("WEB-INF/oidc.json");
					}

					if (jsonNode != null && jsonNode.getAsset() != null) {
						oidcJson = jsonNode.getAsset().openStream();
					}
				} catch (IOException e) {
					// ignore
					// e.printStackTrace();
				}
			}
		}

		// Setup web.xml
		this.asset.setContextParam("resteasy.scan", "true");

		if (oidcJson != null) {
			getArchive().as(JARArchive.class).add(new ByteArrayAsset(oidcJson), "WEB-INF/oidc.json");
		} else {
			// not adding it.
		}
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