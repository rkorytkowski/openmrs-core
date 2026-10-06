/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.security;

import org.openmrs.OpenmrsObject;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory.TargetVisitor;
import org.springframework.stereotype.Component;

/**
 * TRUNK-6803 spike: wraps Spring's authorization proxy for an {@link OpenmrsObject} in one whose
 * {@code equals}/{@code hashCode} still work (see {@link DelegatingAuthorizationProxy}). Registered
 * by {@code AuthorizationProxyConfiguration}, which collects {@code TargetVisitor} beans.
 */
@Component
public class OpenmrsObjectTargetVisitor implements TargetVisitor {

	// re-entry guard: building the inner proxy calls back into the factory, where this visitor must
	// stand aside so Spring's own CGLIB proxy gets built
	private static final ThreadLocal<Boolean> BUILDING = new ThreadLocal<>();

	@Override
	public Object visit(AuthorizationAdvisorProxyFactory proxyFactory, Object target) {
		if (!(target instanceof OpenmrsObject) || Boolean.TRUE.equals(BUILDING.get())) {
			return null;
		}

		BUILDING.set(Boolean.TRUE);
		try {
			return DelegatingAuthorizationProxy.wrap(target, proxyFactory.proxy(target));
		} finally {
			BUILDING.remove();
		}
	}
}
