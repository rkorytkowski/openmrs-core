/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.web.security;

import jakarta.servlet.Filter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Proves the bean {@code web.xml}'s {@code DelegatingFilterProxy} looks up by name
 * ({@code springSecurityFilterChain}) actually exists and is a {@link Filter} once
 * {@link WebSecurityConfig} is loaded - this is easy to get backwards, since
 * {@code @EnableWebSecurity} auto-registers its own {@code Filter} bean under that exact name,
 * separate from any {@code @Bean SecurityFilterChain} method (see the javadoc on
 * {@link WebSecurityConfig#openmrsSecurityFilterChain(org.springframework.security.config.annotation.web.builders.HttpSecurity)}).
 * A naming collision here would only surface as a servlet-container startup failure, not a compile
 * or unit-test failure of {@link WebSecurityConfig} in isolation.
 */
class WebSecurityConfigTest {

	private AnnotationConfigApplicationContext context;

	@AfterEach
	void closeContext() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	void contextLoads_shouldExposeAFilterBeanNamedSpringSecurityFilterChain() {
		context = new AnnotationConfigApplicationContext(WebSecurityConfig.class);

		Object bean = context.getBean("springSecurityFilterChain");
		assertNotNull(bean);
		org.junit.jupiter.api.Assertions.assertInstanceOf(Filter.class, bean);
	}

	/**
	 * {@code FilterChainProxy} defaults to a strict firewall that answers 403 before any OpenMRS filter
	 * runs, so each of these shapes - all of which reach OpenMRS legitimately - would be rejected
	 * without {@link WebSecurityConfig#httpFirewall()}. Driven through the bean the real context
	 * publishes, since the point is the configuration, not {@code StrictHttpFirewall} itself.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/openmrs/index.htm;jsessionid=ABC123", "/openmrs//index.htm",
	        "/openmrs/ws/rest/v1/concept%2Fx", "/openmrs/moduleResources/a%2eb" })
	void httpFirewall_shouldAcceptTheUrlShapesOpenmrsServes(String requestUri) {
		assertDoesNotThrow(() -> firewalled(requestUri));
	}

	/**
	 * The relaxations above are deliberately narrow - a backslash, an encoded percent and a NUL carry
	 * no legitimate meaning in an OpenMRS URL, and each is a known path-traversal or double-decoding
	 * evasion, so the strict defaults stay in force for them.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/openmrs/a\\b", "/openmrs/a%25b", "/openmrs/a%00b" })
	void httpFirewall_shouldStillRejectTheDangerousShapes(String requestUri) {
		assertThrows(RequestRejectedException.class, () -> firewalled(requestUri));
	}

	private void firewalled(String requestUri) {
		context = new AnnotationConfigApplicationContext(WebSecurityConfig.class);
		HttpFirewall firewall = context.getBean(HttpFirewall.class);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setRequestURI(requestUri);

		firewall.getFirewalledRequest(request);
	}
}
