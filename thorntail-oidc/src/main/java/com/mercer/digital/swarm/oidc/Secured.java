

package com.mercer.digital.swarm.oidc;

import org.jboss.shrinkwrap.api.Assignable;
import org.wildfly.swarm.undertow.descriptors.SecurityConstraint;

public interface Secured extends Assignable {

	SecurityConstraint protect();

	SecurityConstraint protect(String urlPattern);

}
