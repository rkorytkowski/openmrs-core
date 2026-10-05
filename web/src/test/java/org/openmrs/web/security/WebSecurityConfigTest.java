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
import org.springframework.security.web.firewall.StrictHttpFirewall;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
	 * This config publishes no {@link HttpFirewall}, so {@code FilterChainProxy} keeps its strict
	 * default. Each of these shapes is one the container decodes or normalizes before choosing a
	 * servlet, while a URL rule matches the raw request URI - so accepting them is what would let a
	 * rule be walked around, and rejecting them is the point. {@code ;jsessionid=} is included because
	 * {@code web.xml} asks for cookie-only session tracking, so the container never writes it.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/openmrs/index.htm;jsessionid=ABC123", "/openmrs/x/..;/admin/y", "/openmrs/x/%2E%2E/admin/y",
	        "/openmrs/a\\b", "/openmrs/a%25b", "/openmrs/a%00b" })
	void httpFirewall_shouldRejectTheShapesThatCouldWalkAroundAUrlRule(String requestUri) {
		assertThrows(RequestRejectedException.class, () -> firewalled(requestUri));
	}

	@Test
	void httpFirewall_shouldNotBeOverriddenByThisConfig() {
		context = new AnnotationConfigApplicationContext(WebSecurityConfig.class);

		// a relaxation would have to come from an HttpFirewall bean - FilterChainProxy's firewall is not
		// reachable through HttpSecurity - so the absence of one is what keeps the strict default
		assertTrue(context.getBeansOfType(HttpFirewall.class).isEmpty());
	}

	private void firewalled(String requestUri) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setRequestURI(requestUri);

		new StrictHttpFirewall().getFirewalledRequest(request);
	}
}
