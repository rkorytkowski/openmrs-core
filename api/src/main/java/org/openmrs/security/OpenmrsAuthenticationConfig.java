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

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;

/**
 * Registers the Spring Security {@link AuthenticationManager} used by
 * {@link org.openmrs.api.context.UserContext#authenticate(org.openmrs.api.context.Credentials)} as
 * the real entry point for authentication, wrapping
 * {@link AuthenticationSchemeAuthenticationProvider}.
 *
 * @since 3.0.0
 */
@Configuration
public class OpenmrsAuthenticationConfig {

	@Bean(name = "authenticationManager")
	public AuthenticationManager authenticationManager(AuthenticationSchemeAuthenticationProvider provider) {
		return new ProviderManager(List.<AuthenticationProvider> of(provider));
	}
}
