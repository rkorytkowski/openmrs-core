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

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.hibernate.proxy.HibernateProxy;
import org.openmrs.api.context.Context;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.ClassUtils;

/**
 * Lets {@code @PreAuthorize}/{@code @PostAuthorize}/{@code @PostFilter} expressions check OpenMRS
 * privileges, e.g. {@code @PreAuthorize("hasPermission(null, 'Get Providers')")}. This is the
 * preferred way to enforce authorization as of 3.0.0, superseding the deprecated
 * {@link org.openmrs.annotation.Authorized} (see {@code doc/AUTHORIZATION_MIGRATION.md}). It
 * delegates to {@link Context#hasPrivilege(String)}, the same method {@code AuthorizationAdvice}
 * uses, so both mechanisms decide a privilege identically - superuser status, the implicit
 * Anonymous/Authenticated roles, proxy privileges and the {@code Daemon} bypass included, none of
 * which a flat authority set can express (see {@link OpenmrsAuthenticationToken#getAuthorities()}).
 * <p>
 * The built-in {@code hasAuthority('&lt;privilege&gt;')} resolves the same way, through
 * {@link OpenmrsAuthorizationManagerFactory}, so for a bare privilege check neither form is wrong.
 * What this one adds is the target: when a call names one -
 * {@code hasPermission(targetDomainObject, permission)} or
 * {@code hasPermission(targetId, targetType, permission)} - every registered
 * {@link DomainObjectAuthorizationRule} for that target's type must authorize it too, on top of the
 * privilege (most-restrictive-wins). Rules are grouped by type in the constructor rather than
 * filtered per call, since this may run once per element of a {@code @PostFilter}ed collection.
 * Core registers none, so a target with no rule for its type is authorized on the privilege alone -
 * this is purely additive for modules needing per-instance access control.
 * <p>
 * A plain predicate: a missing privilege, or a rule that denies, returns {@code false} and never
 * throws, because SpEL composes these. {@code hasPermission(null, 'A') or hasPermission(null, 'B')}
 * is the translation of a multi-privilege {@code @Authorized}, and
 * {@code @PreFilter}/{@code @PostFilter} evaluate once per element and want a verdict. Throwing
 * would stop the {@code or} reaching its second operand and make a filter pass everything or fail
 * outright. Naming the privilege in a denial therefore happens one level out, in
 * {@link PrivilegeNamingAuthorizationManager}, from what {@link MissingPrivilegeRecorder} collected
 * - only if the whole expression denied. A denial from a rule records nothing and so keeps the
 * generic message, correctly: every privilege the expression named was in fact held.
 * <p>
 * A no-value {@code @Authorized} needs nothing here: {@code @PreAuthorize("isAuthenticated()")} is
 * faithful, since {@link OpenmrsAuthenticationToken#isAuthenticated()} covers the same
 * Daemon-thread and proxy-privilege cases.
 *
 * @since 3.0.0
 */
@Component
public class OpenmrsPermissionEvaluator implements PermissionEvaluator {

	private final Map<String, List<DomainObjectAuthorizationRule>> rulesByType;

	@Autowired
	public OpenmrsPermissionEvaluator(List<DomainObjectAuthorizationRule> rules) {
		this.rulesByType = rules.stream().collect(Collectors.groupingBy(DomainObjectAuthorizationRule::getTargetType));
	}

	@Override
	public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
		if (!holdsPrivilege(permission)) {
			return false;
		}
		if (targetDomainObject == null) {
			return true;
		}

		for (DomainObjectAuthorizationRule rule : rulesByType.getOrDefault(targetTypeOf(targetDomainObject), List.of())) {
			if (!rule.isAuthorized(authentication, targetDomainObject, permission)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
	        Object permission) {
		if (!holdsPrivilege(permission)) {
			return false;
		}
		if (targetId == null) {
			return true;
		}

		for (DomainObjectAuthorizationRule rule : rulesByType.getOrDefault(targetType, List.of())) {
			if (!rule.isAuthorized(authentication, targetId, targetType, permission)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The entity type behind {@code target}, unwrapping a Hibernate or Spring AOP proxy so a rule
	 * registered for {@code Obs} still matches a lazily loaded or
	 * {@code @AuthorizeReturnObject}-proxied one. Reads the persistent class rather than the
	 * implementation: resolving the type must not initialize a lazy proxy, because this runs once per
	 * element of a {@code @PostFilter}ed collection.
	 */
	private static String targetTypeOf(Object target) {
		if (target instanceof HibernateProxy hibernateProxy) {
			return hibernateProxy.getHibernateLazyInitializer().getPersistentClass().getSimpleName();
		}

		return ClassUtils.getUserClass(AopProxyUtils.ultimateTargetClass(target)).getSimpleName();
	}

	/**
	 * The privilege half of the check, shared by both overloads: true if the current user holds
	 * {@code permission}, otherwise false with the name handed to {@link MissingPrivilegeRecorder} so a
	 * denial can report it (see the class javadoc).
	 */
	private boolean holdsPrivilege(Object permission) {
		if (permission == null) {
			return false;
		}

		String privilege = permission.toString();
		if (PrivilegeResolution.holdsPrivilege(privilege)) {
			return true;
		}

		MissingPrivilegeRecorder.record(privilege);
		return false;
	}
}
