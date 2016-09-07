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

package com.mercer.cpsg.swarm.oidc;

import javax.annotation.PostConstruct;
import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

import org.wildfly.swarm.spi.api.Fraction;

public class OIDCFraction implements Fraction<OIDCFraction> {

	private boolean inhibitDefaultSecurityDomain = false;
	private OIDC<?> config = new OIDC();

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
			consumer.accept(config);
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

	@Produces
	@Singleton
	public OIDC<?> config() {
		return config;
	}

	@Override
	public OIDCFraction applyDefaults() {
		return this;
	}

	@FunctionalInterface
	public static interface OIDCConsumer {

		void accept(OIDC<?> value);

		default OIDCConsumer andThen(OIDCConsumer after) {
			return (c) -> {
				this.accept(c);
				after.accept(c);
			};
		}
	}

}
