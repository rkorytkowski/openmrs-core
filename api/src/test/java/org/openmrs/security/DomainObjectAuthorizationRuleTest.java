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

import org.junit.jupiter.api.Test;
import org.openmrs.test.jupiter.BaseContextSensitiveTest;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies how {@link OpenmrsPermissionEvaluator} consults registered
 * {@link DomainObjectAuthorizationRule} beans: a target with no rule registered for its type is
 * authorized by default, a supporting rule can deny it, several supporting rules combine with
 * most-restrictive- wins, and a rule registered for an unrelated type is never consulted. Runs as a
 * {@link BaseContextSensitiveTest} only so {@code Context.hasPrivilege(...)} - which the underlying
 * privilege check still requires - has an authenticated (superuser) context to resolve against; the
 * evaluator itself is constructed directly with hand-built rules rather than autowired, so each
 * test controls exactly which rules are in play.
 */
public class DomainObjectAuthorizationRuleTest extends BaseContextSensitiveTest {

	private static final String PRIVILEGE = "Some Privilege";

	private static class TestTarget {}

	private static class AnotherTestTarget {}

	/**
	 * Records whether it was consulted, so a test can assert a rule for an unrelated type - or one that
	 * should never be reached because the base privilege check already failed - was skipped rather than
	 * merely happening to agree.
	 */
	private static class FakeRule implements DomainObjectAuthorizationRule {

		private final String targetType;

		private final boolean authorized;

		private boolean called = false;

		FakeRule(String targetType, boolean authorized) {
			this.targetType = targetType;
			this.authorized = authorized;
		}

		@Override
		public String getTargetType() {
			return targetType;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			called = true;
			return authorized;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, String targetType,
		        Object permission) {
			called = true;
			return authorized;
		}

		boolean wasCalled() {
			return called;
		}
	}

	@Test
	public void hasPermission_shouldAuthorizeATargetWithNoRuleRegisteredForItsType() {
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of());

		assertTrue(evaluator.hasPermission(null, new TestTarget(), PRIVILEGE));
		assertTrue(evaluator.hasPermission(null, 1, "TestTarget", PRIVILEGE));
	}

	@Test
	public void hasPermission_shouldDenyWhenTheSupportingRuleDenies() {
		FakeRule denies = new FakeRule("TestTarget", false);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(denies));

		assertFalse(evaluator.hasPermission(null, new TestTarget(), PRIVILEGE));
		assertTrue(denies.wasCalled());
	}

	@Test
	public void hasPermission_shouldDenyWhenTheSupportingRuleDeniesByIdAndType() {
		FakeRule denies = new FakeRule("TestTarget", false);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(denies));

		assertFalse(evaluator.hasPermission(null, 1, "TestTarget", PRIVILEGE));
		assertTrue(denies.wasCalled());
	}

	@Test
	public void hasPermission_shouldAuthorizeWhenEverySupportingRuleAgrees() {
		FakeRule first = new FakeRule("TestTarget", true);
		FakeRule second = new FakeRule("TestTarget", true);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(first, second));

		assertTrue(evaluator.hasPermission(null, new TestTarget(), PRIVILEGE));
		assertTrue(first.wasCalled());
		assertTrue(second.wasCalled());
	}

	@Test
	public void hasPermission_shouldBeMostRestrictiveWinsWhenSupportingRulesDisagree() {
		FakeRule allows = new FakeRule("TestTarget", true);
		FakeRule denies = new FakeRule("TestTarget", false);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(allows, denies));

		assertFalse(evaluator.hasPermission(null, new TestTarget(), PRIVILEGE));
	}

	@Test
	public void hasPermission_shouldNeverConsultARuleRegisteredForAnUnrelatedType() {
		FakeRule deniesEverythingForAnotherType = new FakeRule("AnotherTestTarget", false);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(deniesEverythingForAnotherType));

		assertTrue(evaluator.hasPermission(null, new TestTarget(), PRIVILEGE));
		assertFalse(deniesEverythingForAnotherType.wasCalled());
	}

	@Test
	public void hasPermission_shouldNotConsultRulesWhenTheBasePrivilegeCheckAlreadyFails() {
		FakeRule wouldAuthorize = new FakeRule("TestTarget", true);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(wouldAuthorize));

		assertFalse(evaluator.hasPermission(null, new TestTarget(), null));
		assertFalse(wouldAuthorize.wasCalled());
	}

	@Test
	public void hasPermission_shouldAuthorizeANullTargetWithoutConsultingAnyRule() {
		FakeRule wouldDeny = new FakeRule("TestTarget", false);
		OpenmrsPermissionEvaluator evaluator = new OpenmrsPermissionEvaluator(List.of(wouldDeny));

		assertTrue(evaluator.hasPermission(null, (Object) null, PRIVILEGE));
		assertTrue(evaluator.hasPermission(null, null, "TestTarget", PRIVILEGE));
		assertFalse(wouldDeny.wasCalled());
	}
}
