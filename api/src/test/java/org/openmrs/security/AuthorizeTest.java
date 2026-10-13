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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.openmrs.Encounter;
import org.openmrs.Obs;
import org.openmrs.Patient;
import org.openmrs.PersonName;
import org.openmrs.api.APIException;
import org.openmrs.api.context.Context;
import org.openmrs.test.jupiter.BaseContextSensitiveTest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers {@link Authorize}, the presentation-layer side of {@link DomainObjectAuthorizationRule}: a
 * rule's verdict applied to what is about to be serialized, with what it refuses replaced rather
 * than dropped so a reader can tell hidden from absent.
 * <p>
 * The properties worth pinning are the ones a serializer depends on and the one that keeps the
 * whole approach safe: a mask is still the declared type, it discloses only its identifiers, a
 * collection keeps its size, and a mask is refused by the write path instead of reaching Hibernate.
 * <p>
 * {@link MaskingPatientRule} is registered for the whole suite, like the other rules in these
 * tests, and refuses nothing until a test names a patient.
 */
public class AuthorizeTest extends BaseContextSensitiveTest {

	@AfterEach
	public void disarmRule() {
		MaskingPatientRule.deniedPatientId = null;
		DenyingPersonNameRule.deniedPersonNameId = null;
	}

	private Patient patient(int id) {
		return Context.getPatientService().getPatient(id);
	}

	@Test
	public void maskIfDenied_shouldViewAnObjectNoRuleRefuses() {
		Patient patient = patient(2);

		Patient viewed = Authorize.maskIfDenied(patient);

		// not the same instance: a view, so its own getters are answered through the rules too
		assertInstanceOf(FieldMaskedObject.class, viewed);
		assertFalse(Authorize.isMasked(viewed), "a view holds real data and must not read as masked");
		assertEquals(patient.getUuid(), viewed.getUuid());
		assertEquals(patient.getGender(), viewed.getGender());
	}

	@Test
	public void maskIfDenied_shouldMaskTheObjectWhenARuleRefusesIt() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;

		Patient masked = Authorize.maskIfDenied(patient);

		assertTrue(Authorize.isMasked(masked));
		// still the declared type, so it serializes where the real object would have
		assertNotNull(masked);
		assertEquals(Patient.class, ((MaskedObject) masked).getMaskedType());
	}

	@Test
	public void maskIfDenied_shouldDiscloseNothingAboutTheObjectItMasks() {
		Patient patient = patient(2);
		String uuid = patient.getUuid();
		assertNotNull(patient.getPersonName(), "the premise: this patient has a name to hide");
		MaskingPatientRule.deniedPatientId = 2;

		Patient masked = Authorize.maskIfDenied(patient);

		// a substitute identity rather than the real one: returning the uuid of a record the caller was
		// refused would confirm it exists and hand over a key to try elsewhere
		assertTrue(masked.getUuid().startsWith(Authorize.MASKED_UUID_PREFIX));
		assertNotEquals(uuid, masked.getUuid());
		assertNull(masked.getId());
		assertNull(masked.getPersonName(), "a getter the mask does not recognize must not reach the real object");
		assertNull(masked.getGender());
		// a collection getter comes back empty rather than null: a serializer handed null where it
		// expected a collection fails on the response it is halfway through writing
		assertTrue(masked.getNames().isEmpty());
		assertFalse(masked.getVoided());
	}

	@Test
	public void maskIfDenied_shouldReportOneStableIdentityPerMaskAndNoneAcrossMasks() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;

		Patient masked = Authorize.maskIfDenied(patient);
		Patient maskedAgain = Authorize.maskIfDenied(patient);

		// stable while one object is written out, since a representation reads the uuid more than once
		assertEquals(masked.getUuid(), masked.getUuid());
		// and stable for nothing else: two masks of one record must not be correlatable
		assertNotEquals(masked.getUuid(), maskedAgain.getUuid());
	}

	@Test
	public void maskIfDenied_shouldReportAUuidAFhirIdAccepts() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;

		String uuid = Authorize.maskIfDenied(patient).getUuid();

		// the reason a substitute is reported at all rather than nothing: fhir2's translators set
		// Resource.id from the uuid, and a resource with no id cannot sit in a searchset bundle, whose
		// entry.fullUrl is built from it. FHIR constrains an id to [A-Za-z0-9-.]{1,64}
		assertTrue(uuid.matches("[A-Za-z0-9\\-.]{1,64}"), uuid);

		// and a well-formed uuid besides, so anything that parses one is not handed something it rejects
		assertEquals(uuid, UUID.fromString(uuid).toString());
		assertEquals(4, UUID.fromString(uuid).version(), "the random groups keep a version 4 uuid's bits");
	}

	@Test
	public void maskIfDenied_shouldSerializeAMaskedObject() {
		// fetched before the rule is armed: getPatient is itself guarded by it
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;
		Patient masked = Authorize.maskIfDenied(patient);

		// the point of masking rather than nulling: whatever is about to write JSON still can
		assertDoesNotThrow(() -> new ObjectMapper().writeValueAsString(masked.getUuid()));
		assertDoesNotThrow(() -> masked.toString());
	}

	@Test
	public void maskIfDenied_shouldRefuseAWriteToAMaskedObject() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;
		Patient masked = Authorize.maskIfDenied(patient);

		assertThrows(UnsupportedOperationException.class, () -> masked.setGender("F"));
	}

	@Test
	public void maskIfDenied_shouldLeaveANullObjectAlone() {
		assertNull(Authorize.maskIfDenied((Patient) null));
	}

	@Test
	public void maskIfDenied_shouldKeepTheSizeAndReplaceOnlyWhatARuleRefuses() {
		List<Patient> patients = new ArrayList<>(List.of(patient(2), patient(6)));
		MaskingPatientRule.deniedPatientId = 2;

		Collection<Patient> filtered = Authorize.maskIfDenied(patients);

		assertEquals(2, filtered.size(), "a replaced entry still counts, so six with two hidden is not four");
		List<Patient> asList = new ArrayList<>(filtered);
		assertTrue(Authorize.isMasked(asList.get(0)));
		assertFalse(Authorize.isMasked(asList.get(1)));
		assertEquals(6, asList.get(1).getId(), "order is preserved");
	}

	@Test
	public void maskIfDenied_shouldNotMutateTheCollectionItWasGiven() {
		List<Patient> patients = new ArrayList<>(List.of(patient(2)));
		MaskingPatientRule.deniedPatientId = 2;

		Authorize.maskIfDenied(patients);

		// unlike @PostFilter, which filters in place - the reason a @PostFilter'ed @Cacheable method
		// has to key its cache by the caller
		assertEquals(1, patients.size());
		assertFalse(Authorize.isMasked(patients.get(0)));
	}

	@Test
	public void maskIfDenied_shouldLeaveANullCollectionAlone() {
		assertNull(Authorize.maskIfDenied((Collection<Patient>) null));
	}

	@Test
	public void save_shouldRejectAMaskedObjectRatherThanPersistIt() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;
		Patient masked = Authorize.maskIfDenied(patient);
		MaskingPatientRule.deniedPatientId = null;

		// the constraint the whole approach rests on: a mask carries no data, so saving one would blank
		// the record it stands for, and as a proxy it would be inserted as new
		APIException thrown = assertThrows(APIException.class, () -> Context.getPatientService().savePatient(masked));
		assertTrue(thrown.getMessage().contains("cannot be written"), thrown.getMessage());
	}

	@Test
	public void save_shouldRejectAMaskedObjectInsideACollectionArgument() {
		Patient patient = patient(2);
		MaskingPatientRule.deniedPatientId = 2;
		Patient masked = Authorize.maskIfDenied(patient);
		MaskingPatientRule.deniedPatientId = null;

		assertThrows(APIException.class, () -> Context.getPatientService().mergePatients(patient(6), List.of(masked)));
	}

	@Test
	public void maskIfDenied_shouldConsultNoRuleForATypeNoneCovers() {
		Obs obs = new Obs();
		obs.setUuid("an-obs-no-rule-covers");

		// no Obs rule is registered, so this is the additive case: nothing refuses it, and what comes
		// back is a view whose own getters are answered the same way
		assertFalse(Authorize.isMasked(Authorize.maskIfDenied(obs)));
	}

	@Test
	public void maskIfDenied_shouldMaskADeniedObjectReachedThroughAGetter() {
		Encounter encounter = Context.getEncounterService().getEncounter(3);
		Integer patientId = encounter.getPatient().getPatientId();
		MaskingPatientRule.deniedPatientId = patientId;

		Encounter viewed = Authorize.maskIfDenied(encounter);

		assertTrue(Authorize.isMasked(viewed.getPatient()), "a refused object one getter down is masked");
		assertEquals(3, viewed.getEncounterId(), "the encounter's own data is untouched");
		assertNotNull(viewed.getEncounterDatetime());
	}

	@Test
	public void maskIfDenied_shouldMaskADeniedObjectTwoGettersDown() {
		Encounter encounter = Context.getEncounterService().getEncounter(3);
		Patient patient = encounter.getPatient();
		assertNotNull(patient.getPersonName(), "the premise: there is a name two getters down to hide");
		DenyingPersonNameRule.deniedPersonNameId = patient.getPersonName().getPersonNameId();

		Encounter viewed = Authorize.maskIfDenied(encounter);

		// the patient is allowed, so it comes back as a view in its turn - which is what carries the
		// check another level down
		Patient viewedPatient = viewed.getPatient();
		assertFalse(Authorize.isMasked(viewedPatient));
		assertTrue(Authorize.isMasked(viewedPatient.getPersonName()));
	}

	@Test
	public void maskIfDenied_shouldMaskPerElementOfACollectionGetter() {
		Encounter encounter = Context.getEncounterService().getEncounter(3);
		MaskingPatientRule.deniedPatientId = encounter.getPatient().getPatientId();

		// the collection route down, rather than the single-object one
		Collection<Patient> patients = Authorize.maskIfDenied(List.of(encounter)).stream().map(Encounter::getPatient)
		        .toList();

		assertEquals(1, patients.size());
		assertTrue(Authorize.isMasked(patients.iterator().next()));
	}

	@Test
	public void maskIfDenied_shouldKeepTheDeclaredCollectionTypeOfAGetter() {
		Patient viewed = Authorize.maskIfDenied(patient(2));

		// Person.getAddresses() and getNames() declare Set: handing back a List fails the generated
		// method's cast, which is how a REST Patient conversion broke on the proxy
		assertInstanceOf(Set.class, viewed.getAddresses());
		assertInstanceOf(Set.class, viewed.getNames());
		assertInstanceOf(List.class, viewed.getActiveIdentifiers());
	}

	@Test
	public void maskIfDenied_shouldJudgeMapValuesAndLeaveKeysAlone() {
		Patient patient = patient(2);
		Patient viewed = Authorize.maskIfDenied(patient);

		// keys are attribute names, and masking one would break every lookup against the map
		assertEquals(patient.getAttributeMap().keySet(), viewed.getAttributeMap().keySet());
	}

	@Test
	public void maskIfDenied_shouldNotWrapAMaskOrAViewAgain() {
		Patient patient = patient(2);
		Patient viewed = Authorize.maskIfDenied(patient);

		assertSame(viewed, Authorize.maskIfDenied(viewed), "a view is not viewed again");

		MaskingPatientRule.deniedPatientId = 2;
		Patient masked = Authorize.maskIfDenied(patient);
		assertSame(masked, Authorize.maskIfDenied(masked), "a mask is not wrapped either");
	}

	@Test
	public void save_shouldRejectAFieldMaskedViewRatherThanPersistIt() {
		Patient viewed = Authorize.maskIfDenied(patient(2));
		assertInstanceOf(FieldMaskedObject.class, viewed, "the premise: this has to be a view to be refused as one");

		// a view holds the real object, but it is still a proxy, so Hibernate would insert it as new
		APIException thrown = assertThrows(APIException.class, () -> Context.getPatientService().savePatient(viewed));
		assertTrue(thrown.getMessage().startsWith("A field-masked view of"), thrown.getMessage());
	}

	/** Refuses one test-selected person name, to reach two getters down from an encounter. */
	@Component
	public static class DenyingPersonNameRule implements DomainObjectAuthorizationRule {

		static volatile Integer deniedPersonNameId;

		@Override
		public Class<?> getTargetType() {
			return PersonName.class;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			if (deniedPersonNameId == null || !(targetDomainObject instanceof PersonName name)) {
				return true;
			}
			return !deniedPersonNameId.equals(name.getPersonNameId());
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, Class<?> targetType,
		        Object permission) {
			if (deniedPersonNameId == null) {
				return true;
			}
			return targetId instanceof Integer id && !deniedPersonNameId.equals(id);
		}
	}

	/**
	 * Refuses exactly one, test-selected patient, authorizing every other target. Off by default so
	 * registering it does not change behavior for tests that do not use it.
	 */
	@Component
	public static class MaskingPatientRule implements DomainObjectAuthorizationRule {

		static volatile Integer deniedPatientId;

		@Override
		public Class<?> getTargetType() {
			return Patient.class;
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Object targetDomainObject, Object permission) {
			if (deniedPatientId == null || !(targetDomainObject instanceof Patient patient)) {
				return true;
			}
			return !deniedPatientId.equals(patient.getPatientId());
		}

		@Override
		public boolean isAuthorized(Authentication authentication, Serializable targetId, Class<?> targetType,
		        Object permission) {
			if (deniedPatientId == null) {
				return true;
			}
			// an id form this rule cannot interpret denies, as DomainObjectAuthorizationRule requires
			return targetId instanceof Integer id && !deniedPatientId.equals(id);
		}
	}
}
