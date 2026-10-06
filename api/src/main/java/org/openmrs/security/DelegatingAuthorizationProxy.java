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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import javassist.util.proxy.Proxy;
import javassist.util.proxy.ProxyFactory;

import org.springframework.security.authorization.method.AuthorizationProxy;

/**
 * TRUNK-6803 spike: an authorization proxy whose {@code equals}/{@code hashCode} delegate to the
 * target, which Spring's own CGLIB proxy cannot do - {@code CglibAopProxy}'s callback filter routes
 * both to its own interceptors before any advice runs, so a Spring proxy never equals the entity it
 * wraps. Everything else is forwarded to Spring's proxy, so method security still applies.
 */
final class DelegatingAuthorizationProxy {

	private DelegatingAuthorizationProxy() {
	}

	static Object wrap(Object target, Object authorizationProxy) {
		try {
			ProxyFactory factory = new ProxyFactory();
			factory.setSuperclass(target.getClass());
			factory.setInterfaces(new Class<?>[] { AuthorizationProxy.class });
			Object proxy = factory.createClass().getDeclaredConstructor().newInstance();
			((Proxy) proxy).setHandler((self, thisMethod, proceed, args) -> {
				if ("toAuthorizedTarget".equals(thisMethod.getName()) && thisMethod.getParameterCount() == 0) {
					return target;
				}

				Object receiver = isIdentityMethod(thisMethod) ? target : authorizationProxy;
				try {
					return thisMethod.invoke(receiver, args);
				} catch (InvocationTargetException e) {
					// reflection wraps it, but a denial has to reach the caller as itself
					throw e.getCause();
				}
			});
			return proxy;
		} catch (ReflectiveOperationException e) {
			throw new IllegalStateException("could not proxy " + target.getClass(), e);
		}
	}

	private static boolean isIdentityMethod(Method method) {
		if ("hashCode".equals(method.getName()) && method.getParameterCount() == 0) {
			return true;
		}
		return "equals".equals(method.getName()) && method.getParameterCount() == 1
		        && method.getParameterTypes()[0] == Object.class;
	}
}
