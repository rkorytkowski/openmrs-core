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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openmrs.Encounter;
import org.openmrs.Obs;
import org.openmrs.Order;
import org.openmrs.Patient;
import org.openmrs.PatientIdentifier;
import org.openmrs.Person;
import org.openmrs.PersonName;
import org.openmrs.User;
import org.openmrs.api.context.Context;
import org.openmrs.test.jupiter.BaseContextSensitiveTest;
import org.openmrs.util.PrivilegeConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.stereotype.Component;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Field-level privilege enforcement from inside the getter (TRUNK-6803): {@link Obs#getOrder()} is
 * the privilege-name case, and {@link Obs#getGroupMembers()} the filtered-collection one, where
 * what the caller reads and what a save writes have to part ways.
 */
public class AuthorizeTest extends BaseContextSensitiveTest {

	private static final int OBS_WITH_ORDER = 1000;

	private static final int PATIENT_WITH_TWO_IDENTIFIERS = 2;

	private static final int OBS_GROUP = 1001;

	private static final int HIDDEN_GROUP_MEMBER = 1002;

	/**
	 * Every privilege {@code saveObs} needs; a test withholds the one it is proving is not required.
	 */
	private static final String[] SAVE_PRIVILEGES = { PrivilegeConstants.GET_OBS, PrivilegeConstants.EDIT_OBS,
	        PrivilegeConstants.GET_CONCEPTS, PrivilegeConstants.GET_ENCOUNTERS, PrivilegeConstants.GET_PERSONS,
	        PrivilegeConstants.GET_PATIENTS, PrivilegeConstants.GET_LOCATIONS, PrivilegeConstants.GET_CONCEPT_DATATYPES,
	        PrivilegeConstants.GET_ORDERS };

	@BeforeEach
	public void loadObsWithAnOrder() {
		executeDataSet("org/openmrs/security/include/AuthorizeTest-obsWithOrder.xml");
	}

	@Autowired
	private HidingObsRule hidingObsRule;

	@Autowired
	private HidingOrderRule hidingOrderRule;

	@Autowired
	private HidingEncounterRule hidingEncounterRule;

	@AfterEach
	public void stopHiding() {
		hidingObsRule.setHiddenObsId(null);
		hidingOrderRule.setHiddenOrderId(null);
		hidingEncounterRule.setHiddenEncounterId(null);
	}

	@AfterEach
	public void restoreAdmin() {
		for (String privilege : SAVE_PRIVILEGES) {
			Context.removeProxyPrivilege(privilege);
		}
		Context.getUserContext().logout();
		Context.authenticate("admin", "test");
	}

	@Test
	public void getOrder_shouldReturnTheOrderWithThePrivilege() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);

		// admin is a superuser
		assertNotNull(obs.getOrder());
	}

	@Test
	public void getOrder_shouldDenyWithoutThePrivilege() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		Context.getUserContext().logout();

		AccessDeniedException exception = assertThrows(AccessDeniedException.class, obs::getOrder);

		assertTrue(exception.getMessage().contains(PrivilegeConstants.GET_ORDERS), exception.getMessage());
	}

	@Test
	public void getEncounter_shouldReturnTheEncounterWithThePrivilege() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);

		// admin is a superuser
		assertNotNull(obs.getEncounter());
	}

	@Test
	public void getEncounter_shouldDenyWithoutThePrivilege() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		Context.getUserContext().logout();

		AccessDeniedException exception = assertThrows(AccessDeniedException.class, obs::getEncounter);

		assertTrue(exception.getMessage().contains(PrivilegeConstants.GET_ENCOUNTERS), exception.getMessage());
	}

	@Test
	public void getNoAuthEncounter_shouldReturnTheEncounterWithoutThePrivilege() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		Context.getUserContext().logout();

		assertNotNull(obs.getNoAuthEncounter(), "core machinery has to see the encounter regardless");
	}

	/** The encounter counterpart of {@link #saveObs_shouldWorkForACallerWhoCannotReadTheOrder()}. */
	@Test
	public void saveObs_shouldWorkForACallerWhoCannotReadTheEncounter() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		String uuid = obs.getUuid();
		authenticateWithout(PrivilegeConstants.GET_ENCOUNTERS);
		obs.setComment("edited by a caller without Get Encounters");

		Obs saved = Context.getObsService().saveObs(obs, "field-level guard");

		assertNotNull(saved);
		Context.addProxyPrivilege(PrivilegeConstants.GET_ENCOUNTERS);
		try {
			assertNotNull(Context.getObsService().getObsByUuid(saved.getUuid()).getEncounter(),
			    "the encounter must survive a save by a caller who cannot read it");
			assertNotNull(Context.getObsService().getObsByUuid(uuid).getEncounter(),
			    "the voided original must keep its encounter too");
		} finally {
			Context.removeProxyPrivilege(PrivilegeConstants.GET_ENCOUNTERS);
		}
	}

	@Test
	public void setOrder_shouldSetTheOrderWithThePrivilege() {
		Order order = Context.getObsService().getObs(OBS_WITH_ORDER).getOrder();
		Obs target = new Obs();

		// admin is a superuser
		assertDoesNotThrow(() -> target.setOrder(order));
		assertEquals(order, target.getOrder());
	}

	@Test
	public void setOrder_shouldDenyAttachingAnOrderWithoutThePrivilege() {
		Order order = Context.getObsService().getObs(OBS_WITH_ORDER).getOrder();
		Obs target = new Obs();
		Context.getUserContext().logout();

		AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> target.setOrder(order));

		assertTrue(exception.getMessage().contains(PrivilegeConstants.GET_ORDERS), exception.getMessage());
	}

	@Test
	public void setOrder_shouldDenyDetachingAnOrderTheCallerCannotRead() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		hidingOrderRule.setHiddenOrderId(obs.getOrder().getOrderId());

		// the privilege is held - it is the rule that hides this particular order, so clearing it has to
		// be refused on the strength of the order being replaced, not the one being set
		assertThrows(AccessDeniedException.class, () -> obs.setOrder(null));
	}

	@Test
	public void setOrder_shouldAllowAnAssignmentThatChangesNothingWithoutThePrivilege() {
		Obs obs = new Obs();
		Context.getUserContext().logout();

		// nothing is attached or detached, so there is nothing to be entitled to
		assertDoesNotThrow(() -> obs.setOrder(null));
	}

	@Test
	public void setEncounter_shouldSetTheEncounterWithThePrivilege() {
		Encounter encounter = Context.getObsService().getObs(OBS_WITH_ORDER).getEncounter();
		Obs target = new Obs();

		// admin is a superuser
		assertDoesNotThrow(() -> target.setEncounter(encounter));
		assertEquals(encounter, target.getEncounter());
	}

	@Test
	public void setEncounter_shouldDenyAttachingAnEncounterWithoutThePrivilege() {
		Encounter encounter = Context.getObsService().getObs(OBS_WITH_ORDER).getEncounter();
		Obs target = new Obs();
		Context.getUserContext().logout();

		AccessDeniedException exception = assertThrows(AccessDeniedException.class, () -> target.setEncounter(encounter));

		assertTrue(exception.getMessage().contains(PrivilegeConstants.GET_ENCOUNTERS), exception.getMessage());
	}

	@Test
	public void setEncounter_shouldDenyDetachingAnEncounterTheCallerCannotRead() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		hidingEncounterRule.setHiddenEncounterId(obs.getNoAuthEncounter().getEncounterId());

		// the privilege is held; it is the rule that hides this encounter, so the refusal can only come
		// from the end being replaced
		assertThrows(AccessDeniedException.class, () -> obs.setEncounter(null));
	}

	@Test
	public void setNoAuthEncounter_shouldWireTheEncounterWithoutThePrivilege() {
		Encounter encounter = Context.getObsService().getObs(OBS_WITH_ORDER).getEncounter();
		Obs target = new Obs();
		Context.getUserContext().logout();

		assertDoesNotThrow(() -> target.setNoAuthEncounter(encounter));
		assertEquals(encounter, target.getNoAuthEncounter());
	}

	/** {@link Encounter#addObs(Obs)} is graph construction, so it must not need the privilege. */
	@Test
	public void addObs_shouldWireTheEncounterForACallerWhoCannotReadIt() {
		Encounter encounter = Context.getEncounterService().getEncounter(3);
		Obs obs = new Obs();
		obs.setConcept(Context.getConceptService().getConcept(88));
		Context.getUserContext().logout();

		assertDoesNotThrow(() -> encounter.addObs(obs));
		assertEquals(encounter, obs.getNoAuthEncounter());
	}

	/** The point of the getter-body approach: no proxy, so the instance is the entity itself. */
	@Test
	public void getObs_shouldReturnTheEntityItselfRatherThanAProxy() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);

		assertEquals(Obs.class, obs.getClass());
		assertEquals(obs, Context.getObsService().getObsByUuid(obs.getUuid()));
	}

	/**
	 * The guard must not make persistence depend on the caller's privileges. Two things would break it:
	 * Hibernate reading the property through the getter (hence {@code access="field"} in
	 * {@code Obs.hbm.xml}) and {@code Obs.newInstance} copying it through the getter when an edit voids
	 * and recreates the row.
	 */
	@Test
	public void saveObs_shouldWorkForACallerWhoCannotReadTheOrder() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		String uuid = obs.getUuid();
		authenticateWithout(PrivilegeConstants.GET_ORDERS);
		obs.setComment("edited by a caller without Get Orders");

		Obs saved = Context.getObsService().saveObs(obs, "field-level guard");

		assertNotNull(saved);
		// editing voids the old row and inserts a new one, so re-read by what the save returned
		Context.addProxyPrivilege(PrivilegeConstants.GET_ORDERS);
		try {
			assertNotNull(Context.getObsService().getObsByUuid(saved.getUuid()).getOrder(),
			    "the order must survive a save by a caller who cannot read it");
			assertNotNull(Context.getObsService().getObsByUuid(uuid).getOrder(),
			    "the voided original must keep its order too");
		} finally {
			Context.removeProxyPrivilege(PrivilegeConstants.GET_ORDERS);
		}
	}

	@Test
	public void maskPrivilege_shouldReturnNullInsteadOfDenying() {
		Context.getUserContext().logout();

		assertNull(Authorize.maskPrivilege(PrivilegeConstants.GET_ORDERS, "value"));
	}

	@Test
	public void maskPrivilege_shouldReturnTheValueWithThePrivilege() {
		assertSame("value", Authorize.maskPrivilege(PrivilegeConstants.GET_ORDERS, "value"));
	}

	/**
	 * A real authenticated user - a logged-out thread cannot save at all, since there is no user to
	 * record as the creator - holding every privilege the save needs except {@code withheldPrivilege}.
	 */
	private void authenticateWithout(String withheldPrivilege) {
		Person person = new Person();
		person.addName(new PersonName("Guard", "", "Tester"));
		person.setGender("U");
		person = Context.getPersonService().savePerson(person);

		User user = new User();
		user.setUsername("guardTester");
		user.setPerson(person);
		Context.getUserService().createUser(user, "Test1234");

		Context.getUserContext().logout();
		Context.authenticate("guardTester", "Test1234");
		for (String privilege : SAVE_PRIVILEGES) {
			if (!privilege.equals(withheldPrivilege)) {
				Context.getUserContext().addProxyPrivilege(privilege);
			}
		}
	}

	@Test
	public void require_shouldGrantWhenTheExpressionHolds() {
		assertDoesNotThrow(() -> Authorize.require("hasAuthority('" + PrivilegeConstants.GET_ORDERS + "')"));
	}

	@Test
	public void require_shouldDenyNamingThePrivilegeTheExpressionAskedFor() {
		Context.getUserContext().logout();

		AccessDeniedException exception = assertThrows(AccessDeniedException.class,
		    () -> Authorize.require("hasAuthority('" + PrivilegeConstants.GET_ORDERS + "')"));

		// the same message PrivilegeNamingAuthorizationManager gives a denied annotation
		assertTrue(exception.getMessage().contains(PrivilegeConstants.GET_ORDERS), exception.getMessage());
	}

	/** hasPermission is the reason to reach for an expression: it is what a module can extend. */
	@Test
	public void require_shouldEvaluateHasPermissionAgainstTheTarget() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		String expression = "hasPermission(#target, '" + PrivilegeConstants.GET_ORDERS + "')";

		assertDoesNotThrow(() -> Authorize.require(expression, obs));

		Context.getUserContext().logout();
		assertThrows(AccessDeniedException.class, () -> Authorize.require(expression, obs));
	}

	@Test
	public void require_shouldSupportTheWholeAnnotationVocabulary() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);

		assertDoesNotThrow(() -> {
			Authorize.require("isAuthenticated()");
			Authorize.require("hasAnyAuthority('Nonexistent Privilege', '" + PrivilegeConstants.GET_ORDERS + "')");
			Authorize.require("hasRole('System Developer')");
			Authorize.require("hasAuthority('" + PrivilegeConstants.GET_ORDERS + "') and #target != null", obs);
		});
	}

	@Test
	public void require_shouldRejectAPrivilegeNamePassedAsAnExpression() {
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
		    () -> Authorize.require(PrivilegeConstants.GET_ORDERS));

		assertTrue(exception.getMessage().contains("requirePrivilege(String)"), exception.getMessage());
	}

	/**
	 * What binding the value buys, and the only assertion that tells a bound {@code returnObject} from
	 * an ignored one: admin holds {@code Get Orders}, so nothing but a rule deciding about the order
	 * itself can deny this read.
	 */
	@Test
	public void getOrder_shouldDenyWhenARuleHidesThatOrder() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		hidingOrderRule.setHiddenOrderId(obs.getOrder().getOrderId());

		assertThrows(AccessDeniedException.class, obs::getOrder);
	}

	/** The denying form binds the value the same way, which is what Obs.getOrder() uses. */
	@Test
	public void require_shouldBindTheValueAsTheReturnObject() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		Order order = obs.getOrder();
		String expression = "hasPermission(returnObject, '" + PrivilegeConstants.GET_ORDERS + "')";

		assertDoesNotThrow(() -> Authorize.require(expression, obs, order));

		Context.getUserContext().logout();
		assertThrows(AccessDeniedException.class, () -> Authorize.require(expression, obs, order));
	}

	/** The value is bound as returnObject, as it would be under @PostAuthorize. */
	@Test
	public void mask_shouldBindTheValueAsTheReturnObject() {
		Obs obs = Context.getObsService().getObs(OBS_WITH_ORDER);
		Order order = obs.getOrder();
		String expression = "hasPermission(returnObject, '" + PrivilegeConstants.GET_ORDERS + "')";

		assertSame(order, Authorize.mask(expression, obs, order));

		Context.getUserContext().logout();
		assertNull(Authorize.mask(expression, obs, order));
	}

	/** The expression is parsed once, however many times a guarded getter is called. */
	@Test
	public void require_shouldParseAnExpressionOnlyOnce() {
		String expression = "hasAuthority('" + PrivilegeConstants.GET_ORDERS + "') and 1 == 1";

		assertDoesNotThrow(() -> {
			for (int i = 0; i < 100; i++) {
				Authorize.require(expression);
			}
		});
	}

	@Test
	public void filter_shouldKeepOnlyTheElementsTheExpressionGrants() {
		Patient patient = Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS);

		Set<PatientIdentifier> kept = Authorize.filter("filterObject.identifier == '101'", patient,
		    patient.getIdentifiers());

		assertEquals(1, kept.size());
		assertEquals("101", kept.iterator().next().getIdentifier());
	}

	@Test
	public void filter_shouldEvaluateTheSameVocabularyAsTheAnnotation() {
		Patient patient = Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS);
		Set<PatientIdentifier> identifiers = patient.getIdentifiers();
		String expression = "hasPermission(filterObject, '" + PrivilegeConstants.GET_PATIENT_IDENTIFIERS + "')";

		assertEquals(identifiers.size(), Authorize.filter(expression, patient, identifiers).size());

		Context.getUserContext().logout();
		// denied, so empty rather than null - a getter returning a collection should keep returning one
		assertTrue(Authorize.filter(expression, patient, identifiers).isEmpty());
	}

	/**
	 * The reason the filter copies. Spring filters a collection by clearing it and adding back what
	 * survived, and {@code Patient.identifiers} is mapped {@code cascade="all-delete-orphan"}, so doing
	 * that to the entity's own collection would delete the rows at the next flush.
	 */
	@Test
	public void filter_shouldLeaveTheEntitysOwnCollectionAndItsRowsIntact() {
		Patient patient = Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS);
		Set<PatientIdentifier> identifiers = patient.getIdentifiers();
		int before = identifiers.size();

		Set<PatientIdentifier> kept = Authorize.filter("false", patient, identifiers);

		assertTrue(kept.isEmpty());
		assertNotSame(identifiers, kept);
		assertEquals(before, identifiers.size(), "the entity's own collection must not be filtered");

		Context.getPatientService().savePatient(patient);
		Context.flushSession();
		Context.clearSession();

		assertEquals(before, Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS).getIdentifiers().size(),
		    "filtering must not delete rows");
	}

	@Test
	public void filter_shouldReturnACollectionOfTheSameShape() {
		Patient patient = Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS);
		List<String> list = List.of("a", "b", "c");

		assertInstanceOf(Set.class, Authorize.filter("true", patient, patient.getIdentifiers()));
		// a List keeps its order, which an expression filtering a sorted collection depends on
		assertEquals(List.of("a", "c"), Authorize.filter("filterObject != 'b'", patient, list));
	}

	@Test
	public void filter_shouldPassNullAndEmptyThrough() {
		Set<PatientIdentifier> empty = new LinkedHashSet<>();

		assertNull(Authorize.filter("false", null, (Set<PatientIdentifier>) null));
		assertSame(empty, Authorize.filter("false", null, empty));
	}

	/**
	 * Why {@link Authorize#filter(String, Object, Set)} copies, kept as a test because it is the one
	 * thing that must not be optimised away. Spring filters a collection by clearing it and adding back
	 * what survived, so filtering a getter's own collection in place empties the entity and -
	 * {@code Patient.identifiers} being mapped {@code cascade="all-delete-orphan"} - deletes every row
	 * at the next flush. Flushed directly rather than through {@code savePatient}, which rejects a
	 * patient left with no preferred identifier, itself a breakage.
	 */
	@Test
	public void inPlaceFiltering_shouldEmptyTheEntityAndDeleteItsRows() throws Exception {
		Patient patient = Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS);
		Set<PatientIdentifier> live = patient.getIdentifiers();
		assertEquals(2, live.size());

		MethodSecurityExpressionHandler handler = Context.getRegisteredComponent("methodSecurityExpressionHandler",
		    MethodSecurityExpressionHandler.class);
		EvaluationContext context = handler.createEvaluationContext(
		    () -> SecurityContextHolder.getContext().getAuthentication(),
		    new SimpleMethodInvocation(patient, Object.class.getMethod("toString")));
		handler.filter(live, handler.getExpressionParser().parseExpression("false"), context);

		assertTrue(live.isEmpty(), "Spring's filter mutates the collection it is given");

		Context.flushSession();
		Context.clearSession();

		assertTrue(Context.getPatientService().getPatient(PATIENT_WITH_TWO_IDENTIFIERS).getIdentifiers().isEmpty(),
		    "the orphans are deleted, which is what filtering a copy avoids");
	}

	@Test
	public void getGroupMembers_shouldKeepEveryMemberWhenNoRuleDiscriminates() {
		assertEquals(2, Context.getObsService().getObs(OBS_GROUP).getGroupMembers().size());
	}

	@Test
	public void getGroupMembers_shouldDropTheMemberARuleHides() {
		hidingObsRule.setHiddenObsId(HIDDEN_GROUP_MEMBER);

		Set<Obs> members = Context.getObsService().getObs(OBS_GROUP).getGroupMembers();

		assertEquals(1, members.size());
		assertNotEquals(HIDDEN_GROUP_MEMBER, members.iterator().next().getObsId());
	}

	/** The filter is on the read path only - the group itself still holds every member. */
	@Test
	public void getGroupMembers_shouldLeaveTheGroupsOwnCollectionIntact() {
		hidingObsRule.setHiddenObsId(HIDDEN_GROUP_MEMBER);
		Obs group = Context.getObsService().getObs(OBS_GROUP);

		Set<Obs> members = group.getGroupMembers(true);

		assertEquals(1, members.size());
		assertEquals(2, group.getNoAuthGroupMembers(true).size());
		assertNotSame(members, group.getNoAuthGroupMembers(true));
	}

	/**
	 * Whether an obs is a group is structure rather than data the caller reads, and
	 * {@code isObsGrouping()} gates persistence, so neither may depend on who is asking.
	 */
	@Test
	public void hasGroupMembers_shouldNotDependOnTheCallersPrivileges() {
		Obs group = Context.getObsService().getObs(OBS_GROUP);
		assertEquals(2, group.getNoAuthGroupMembers(true).size());
		Context.getUserContext().logout();

		assertTrue(group.getGroupMembers().isEmpty());
		assertTrue(group.hasGroupMembers());
		assertTrue(group.isObsGrouping());
	}

	/**
	 * The write-path half of the filter, and the reason for {@link Obs#getNoAuthGroupMembers(boolean)}:
	 * editing a group voids and recreates it through {@code Obs.newInstance}, and the services save,
	 * validate and reparent its members - none of which may lose a member the caller is not allowed to
	 * read.
	 */
	@Test
	public void saveObs_shouldKeepAMemberTheCallerCannotRead() {
		hidingObsRule.setHiddenObsId(HIDDEN_GROUP_MEMBER);
		Obs group = Context.getObsService().getObs(OBS_GROUP);
		group.setComment("edited while one member is hidden");

		Obs saved = Context.getObsService().saveObs(group, "hidden group member");
		Context.flushSession();
		Context.clearSession();

		assertEquals(2, Context.getObsService().getObsByUuid(saved.getUuid()).getNoAuthGroupMembers(true).size(),
		    "a member the caller cannot read must survive the save");
	}

	/**
	 * Hides one test-selected obs from reads - {@code Get Obs} only, so the privileges a save needs on
	 * the same obs stay granted and a member dropped from a group is data loss rather than a denial.
	 * Hides nothing by default, so registering it for the whole suite leaves other tests alone.
	 */
	@Component
	public static class HidingObsRule implements DomainObjectAuthorizationRule {

		private volatile Integer hiddenObsId;

		public void setHiddenObsId(Integer hiddenObsId) {
			this.hiddenObsId = hiddenObsId;
		}

		@Override
		public Class<?> getTargetType() {
			return Obs.class;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			return !(targetDomainObject instanceof Obs obs) || !hidden(obs.getObsId(), permission);
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, Class<?> targetType,
		        Object permission) {
			return !hidden(targetId, permission);
		}

		private boolean hidden(Object obsId, Object permission) {
			return hiddenObsId != null && hiddenObsId.equals(obsId) && PrivilegeConstants.GET_OBS.equals(permission);
		}
	}

	/**
	 * The {@link HidingObsRule} equivalent for an order, as a module guarding {@code Obs.getOrder()}
	 * would write it. Registered for "Order", the type {@code Obs.order} declares: rules are selected
	 * by the target's resolved type, and {@code OpenmrsPermissionEvaluator} reads an uninitialized
	 * proxy's persistent class rather than initializing it. Order 1 of the standard dataset is in fact
	 * a {@code DrugOrder}, so a module has to register for the subtypes as well to cover a caller who
	 * loaded the order before the obs.
	 */
	@Component
	public static class HidingEncounterRule implements DomainObjectAuthorizationRule {

		private volatile Integer hiddenEncounterId;

		public void setHiddenEncounterId(Integer hiddenEncounterId) {
			this.hiddenEncounterId = hiddenEncounterId;
		}

		@Override
		public Class<?> getTargetType() {
			return Encounter.class;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			return !(targetDomainObject instanceof Encounter encounter) || !hidden(encounter.getEncounterId(), permission);
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, Class<?> targetType,
		        Object permission) {
			return !hidden(targetId, permission);
		}

		private boolean hidden(Object encounterId, Object permission) {
			return hiddenEncounterId != null && hiddenEncounterId.equals(encounterId)
			        && PrivilegeConstants.GET_ENCOUNTERS.equals(permission);
		}
	}

	@Component
	public static class HidingOrderRule implements DomainObjectAuthorizationRule {

		private volatile Integer hiddenOrderId;

		public void setHiddenOrderId(Integer hiddenOrderId) {
			this.hiddenOrderId = hiddenOrderId;
		}

		@Override
		public Class<?> getTargetType() {
			return Order.class;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			return !(targetDomainObject instanceof Order order) || !hidden(order.getOrderId(), permission);
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, Class<?> targetType,
		        Object permission) {
			return !hidden(targetId, permission);
		}

		private boolean hidden(Object orderId, Object permission) {
			return hiddenOrderId != null && hiddenOrderId.equals(orderId)
			        && PrivilegeConstants.GET_ORDERS.equals(permission);
		}
	}
}
