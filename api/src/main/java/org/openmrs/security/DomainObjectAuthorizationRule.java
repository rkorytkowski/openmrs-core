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

import org.springframework.security.core.Authentication;

/**
 * Extension point for object-level authorization, consulted by {@link OpenmrsPermissionEvaluator}
 * when a {@code @PreAuthorize}/{@code @PostAuthorize}/{@code @PostFilter} expression's
 * {@code hasPermission(...)} call names a target - e.g.
 * {@code @PreAuthorize("hasPermission(#patient, 'Get Patients')")} or
 * {@code @PostFilter("hasPermission(filterObject, 'Get Patients')")}.
 * <p>
 * Core has no built-in notion of per-instance access restriction (no care-setting or organizational
 * unit ACL model), so this interface exists purely for modules to plug one in. Implementations are
 * registered as Spring beans and grouped by {@link #getTargetType()} once, when
 * {@link OpenmrsPermissionEvaluator} is constructed - {@code hasPermission(...)} may run once per
 * element of a large {@code @PostFilter}-ed collection, so which rules apply to a given target type
 * is looked up rather than re-filtered on every call. A target with no rule registered for its type
 * is authorized by default, so adding this extension point never restricts an existing
 * {@code hasPermission(...)} call site that does not name a target, or a target type no registered
 * rule declares.
 * <p>
 * Where more than one registered rule declares the same target type, every one of them must
 * authorize it - most-restrictive-wins, matching how {@code @Authorized}/{@code @PreAuthorize}
 * already combine with the underlying privilege check.
 *
 * @since 3.0.0
 */
public interface DomainObjectAuthorizationRule {

	/**
	 * @return the simple class name (e.g. {@code "Patient"}) of the target type this rule applies to -
	 *         the same convention {@code hasPermission(targetId, targetType, permission)} SpEL
	 *         expressions already use. A rule needing to cover more than one type registers as more
	 *         than one bean.
	 */
	String getTargetType();

	/**
	 * @param authentication the current authentication
	 * @param targetDomainObject the target object named by a
	 *            {@code hasPermission(targetDomainObject, permission)} expression
	 * @param permission the permission argument from the expression (an OpenMRS privilege name, by this
	 *            codebase's convention)
	 * @return true if this rule authorizes access to {@code targetDomainObject}
	 */
	boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission);

	/**
	 * @param authentication the current authentication
	 * @param targetId the target's identifier, named by a
	 *            {@code hasPermission(targetId, targetType, permission)} expression - an
	 *            {@code Integer} primary key (e.g. {@code hasPermission(#patientId, 'Patient', ...)})
	 *            or a {@code String} uuid (e.g. {@code hasPermission(#uuid, 'Patient', ...)}) alike,
	 *            whichever the calling method already has in hand; implementations that only support
	 *            one form should check {@code targetId}'s runtime type and, if unsupported, authorize
	 *            rather than deny (an id form this rule cannot interpret is not evidence of denial)
	 * @param targetType the target's simple class name, from the same expression
	 * @param permission the permission argument from the expression (an OpenMRS privilege name, by this
	 *            codebase's convention)
	 * @return true if this rule authorizes access to the object identified by {@code targetId}
	 */
	boolean isAuthorized(Authentication authentication, Serializable targetId, String targetType, Object permission);
}
