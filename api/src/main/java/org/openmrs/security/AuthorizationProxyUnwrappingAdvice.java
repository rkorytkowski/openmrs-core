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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.ReflectiveMethodInvocation;
import org.springframework.security.authorization.method.AuthorizationProxy;
import org.springframework.stereotype.Component;

/**
 * TRUNK-6803 spike: replaces any {@link AuthorizationProxy} argument with its target before a DAO
 * sees it, so an entity returned by an {@code @AuthorizeReturnObject} method can still be
 * persisted. The DAO boundary is used rather than the service boundary because core re-enters its
 * own services ({@code ObsServiceImpl.saveObs} re-fetches through
 * {@code Context.getObsService().getObs(...)}), so a proxy can appear inside a save that was called
 * with an unwrapped argument.
 */
@Component
public class AuthorizationProxyUnwrappingAdvice implements MethodInterceptor {

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Object[] arguments = invocation.getArguments();
		Object[] unwrapped = null;
		for (int i = 0; i < arguments.length; i++) {
			if (arguments[i] instanceof AuthorizationProxy proxy) {
				if (unwrapped == null) {
					unwrapped = arguments.clone();
				}
				unwrapped[i] = proxy.toAuthorizedTarget();
			}
		}

		if (unwrapped != null && invocation instanceof ReflectiveMethodInvocation reflective) {
			reflective.setArguments(unwrapped);
		}

		return invocation.proceed();
	}
}
