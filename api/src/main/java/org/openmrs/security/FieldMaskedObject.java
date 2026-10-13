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

/**
 * Marks the view {@link Authorize} returns for an object no rule refused: the real object, with
 * every getter that yields a domain object answering through the rules, so a refused one comes back
 * as a {@link MaskedObject} and an allowed one as a view in its turn.
 * <p>
 * Distinct from {@link MaskedObject} because the two are opposites in what they hold. A mask holds
 * nothing and stands in for an object the caller may not read; a view holds everything and hides
 * only what a rule refused. A reader deciding whether to show "hidden" wants the former, so
 * {@link Authorize#isMasked(Object)} must not answer true for the latter.
 * <p>
 * Like a mask, a view must never be written back: it is a proxy, and Hibernate reads a proxied
 * entity as unmanaged and inserts it as new. {@code RequiredDataAdvice} refuses both on their way
 * into a write.
 *
 * @see MaskedObject
 * @since 3.0.0
 */
public interface FieldMaskedObject extends OpenmrsObject {

	/**
	 * @return the type of the object being viewed
	 */
	Class<?> getViewedType();
}
