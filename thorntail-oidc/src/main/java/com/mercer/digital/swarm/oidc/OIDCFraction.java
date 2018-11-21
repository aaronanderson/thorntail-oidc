

package com.mercer.digital.swarm.oidc;


import javax.annotation.PostConstruct;

import org.wildfly.swarm.config.runtime.AttributeDocumentation;
import org.wildfly.swarm.spi.api.Fraction;
import org.wildfly.swarm.spi.api.annotations.Configurable;

public class OIDCFraction implements Fraction<OIDCFraction> {
	
	@Configurable("mercer-digital-wd.oidc.inhibitDefaultSecurityDomain")
	@AttributeDocumentation("Inhibit the default security domain")
	private boolean inhibitDefaultSecurityDomain = false;
	
	/*@Configurable("mercer-digital-wd.oidc.removeAllSecurityConstraints")
	@AttributeDocumentation("Remove all web.xml security constraints. Used in development stage to unprotect the application for expedited development")
	private boolean removeAllSecurityConstraints = false;*/

	
	public static OIDCFraction createDefaultFraction() {
		return new OIDCFraction().applyDefaults();
	}

	@PostConstruct
	public void postConstruct() {
		applyDefaults();
	}

	@SuppressWarnings("unchecked")
	public OIDCFraction config(OIDCConsumer consumer) {
		if (consumer != null) {
			consumer.accept(OIDC.getInstance());
		}
		return this;
	}
	 
	public OIDCFraction inhibitDefaultSecurityDomain() {
		this.inhibitDefaultSecurityDomain = true;
		return this;
	}

	public boolean isInhibitDefaultSecurityDomain() {
		return inhibitDefaultSecurityDomain;
	}

	/*public OIDCFraction removeAllSecurityConstraints() {
		this.removeAllSecurityConstraints = true;
		return this;
	}

	public boolean isRemoveAllSecurityConstraints() {
		return removeAllSecurityConstraints;
	}*/
	
	public OIDC config() {
		return OIDC.getInstance();
	}


	@Override
	public OIDCFraction applyDefaults() {
		return this;
	}

	@FunctionalInterface
	public static interface OIDCConsumer {

		void accept(OIDC value);

		default OIDCConsumer andThen(OIDCConsumer after) {
			return (c) -> {
				this.accept(c);
				after.accept(c);
			};
		}
	}

}
