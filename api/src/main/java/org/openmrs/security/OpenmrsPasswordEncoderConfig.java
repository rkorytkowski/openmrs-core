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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Registers the {@link PasswordEncoder} bean that {@link org.openmrs.util.Security} delegates to
 * for any hash carrying a recognizable {@code {id}} prefix (e.g. {@code {bcrypt}...}). Hashes
 * without a prefix are OpenMRS's pre-3.0.0 legacy format and are verified by
 * {@link org.openmrs.util.Security} directly, unaffected by this bean.
 * <p>
 * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()} defaults new encodings to
 * BCrypt while remaining able to verify several other prefixed formats, matching Spring Security's
 * own recommended default.
 *
 * @since 3.0.0
 */
@Configuration
public class OpenmrsPasswordEncoderConfig {

	@Bean(name = "openmrsPasswordEncoder")
	public PasswordEncoder openmrsPasswordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
