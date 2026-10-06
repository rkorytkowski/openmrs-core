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

import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.openmrs.Obs;
import org.openmrs.api.context.Context;
import org.openmrs.test.jupiter.BaseContextSensitiveTest;
import org.openmrs.util.PrivilegeConstants;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.method.AuthorizationProxy;
import org.springframework.util.ClassUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TRUNK-6803 phase 0 spike. Records what {@code @AuthorizeReturnObject} on
 * {@code ObsService.getObs(Integer)} plus {@code @PreAuthorize} on {@link Obs#getOrder()} actually
 * does to an OpenMRS entity, so the decision to adopt it rests on observed behaviour. Every
 * assertion here is a finding, including the ones that document breakage.
 */
public class AuthorizeReturnObjectSpikeTest extends BaseContextSensitiveTest {

	private static final int OBS_WITH_ORDER = 7;

	/** FINDING: the enforcement mechanism works - this is what the ticket asks for. */
	@Test
	public void spike_shouldEnforceThePrivilegeOnTheGetterItself() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		obs.getOrder(); // admin is a superuser, so this passes

		Context.getUserContext().logout();

		assertThrows(AccessDeniedException.class, obs::getOrder);
	}

	/** FINDING: the returned value is a subclass proxy, not the entity class. */
	@Test
	public void spike_shouldReturnASubclassProxyThatStillPassesAsAnObs() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);

		assertInstanceOf(AuthorizationProxy.class, obs);
		assertInstanceOf(Obs.class, obs);
		assertNotEquals(Obs.class, obs.getClass());
		assertEquals(Obs.class, ClassUtils.getUserClass(obs.getClass()));
	}

	/**
	 * FINDING: {@link DelegatingAuthorizationProxy} restores entity identity, which Spring's own CGLIB
	 * proxy cannot - its callback filter routes {@code equals}/{@code hashCode} to interceptors that
	 * compare proxy configuration, giving asymmetric equality and a {@code Set} that finds neither
	 * instance. Delegating both to the target makes the proxy interchangeable with the entity.
	 */
	@Test
	public void spike_shouldKeepEntityIdentityThroughTheDelegatingProxy() {
		Obs proxied = Context.getObsService().getObs(OBS_WITH_ORDER);
		Obs direct = Context.getObsService().getObsByUuid(proxied.getUuid());

		assertEquals(proxied.getUuid(), direct.getUuid());
		assertTrue(proxied.equals(direct));
		assertTrue(direct.equals(proxied));
		assertEquals(proxied.hashCode(), direct.hashCode());
		assertTrue(new HashSet<>(List.of(direct)).contains(proxied));
		assertTrue(new HashSet<>(List.of(proxied)).contains(direct));
	}

	/**
	 * FINDING: with {@link AuthorizationProxyUnwrappingAdvice} on the DAO boundary, a proxied entity
	 * saves correctly - the proxy never reaches Hibernate, so neither the metadata lookup in
	 * {@code HibernateAdministrationDAO} (itself a {@code @Repository}, so also covered) nor Hibernate
	 * itself ever sees {@code $$SpringCGLIB$$}. Without the advice this threw
	 * {@code APIException: Couldn't find a class in the hibernate configuration named ...SpringCGLIB...}.
	 */
	@Test
	public void spike_shouldSaveTheProxyOnceTheDaoBoundaryUnwrapsIt() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		obs.setComment("spike");

		Obs saved = Context.getObsService().saveObs(obs, "spike round trip");

		assertNotNull(saved);
		// and the state really landed, rather than an empty proxy being written
		assertEquals("spike", Context.getObsService().getObsByUuid(saved.getUuid()).getComment());
	}

	/**
	 * FINDING: the internal re-fetch is covered too. {@code ObsServiceImpl.saveObs} re-reads through
	 * {@code Context.getObsService().getObs(...)}, so a proxy reappears mid-save even when the caller
	 * passed an unwrapped entity; unwrapping at the DAO rather than at the service boundary is what
	 * makes that case work.
	 */
	@Test
	public void spike_shouldSaveAnUnwrappedTargetDespiteTheImplRefetchingThroughTheProxiedMethod() {
		Obs proxied = Context.getObsService().getObs(OBS_WITH_ORDER);
		Obs unwrapped = (Obs) ((AuthorizationProxy) proxied).toAuthorizedTarget();
		unwrapped.setComment("spike unwrapped");

		// editing an obs voids the row and inserts a new one, so the state lands on the saved obs
		Obs saved = Context.getObsService().saveObs(unwrapped, "spike round trip");

		assertNotNull(saved);
		assertEquals("spike unwrapped", Context.getObsService().getObsByUuid(saved.getUuid()).getComment());
	}

	/**
	 * FINDING: the only supported unwrap is {@link AuthorizationProxy#toAuthorizedTarget()} - the
	 * factory calls {@code setOpaque(true)}, so the proxy is not {@code Advised} and
	 * {@code AopProxyUtils.getSingletonTarget} yields null. Unwrapping does restore identity.
	 */
	@Test
	public void spike_shouldOnlyBeUnwrappableThroughAuthorizationProxy() {
		Obs proxied = Context.getObsService().getObs(OBS_WITH_ORDER);
		Obs direct = Context.getObsService().getObsByUuid(proxied.getUuid());

		assertNull(AopProxyUtils.getSingletonTarget(proxied));
		assertInstanceOf(AuthorizationProxy.class, proxied);

		Object target = ((AuthorizationProxy) proxied).toAuthorizedTarget();

		assertEquals(Obs.class, target.getClass());
		assertEquals(direct, target);
	}

	/** Kept to show the getter annotation is inert on an entity that was not proxied. */
	@Test
	public void spike_shouldNotCheckTheGetterOnAnUnproxiedObs() {
		Obs direct = Context.getObsService().getObsByUuid(Context.getObsService().getObs(OBS_WITH_ORDER).getUuid());
		Context.removeProxyPrivilege(PrivilegeConstants.GET_ORDERS);
		Context.getUserContext().logout();

		assertNotNull(direct);
		direct.getOrder(); // no check at all: nothing proxies this instance
	}
}
