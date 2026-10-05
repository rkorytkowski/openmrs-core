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

import java.util.Arrays;

import org.openmrs.security.OpenmrsAuthorizationManagerFactory;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Lets core or a module require an {@link AuthorizationManager} decision to reach a URL pattern -
 * the web-request counterpart of guarding a service method with
 * {@link org.openmrs.annotation.Authorized}, built from Spring Security's own vocabulary
 * ({@code hasAuthority}, {@code hasRole}, {@code AuthorizationManagers.allOf(...)}, or any
 * hand-written manager). Counterpart, not equivalent: {@link OpenmrsAuthorizationFilter} enforces
 * these after {@code ModuleFilter}, so a module filter that completes a request without continuing
 * the chain skips them. A privilege that must hold whatever is installed belongs on the service
 * method; a URL rule narrows access further rather than being the only thing in the way.
 * <p>
 * A rule is a plain value, not a bean: core or a module bundles its rules into one
 * {@link AuthorizedUrlMatchers} bean (see that interface for the registration mechanics).
 * {@link WebSecurityConfig} gathers those once, when the filter bean is built - safe because
 * loading or unloading a module refreshes the context, and {@link RefreshableDelegatingFilterProxy}
 * makes the {@code web.xml} seat pick up the rebuilt bean.
 * <p>
 * {@link #requestMatchers(String...)} is the intended entry point. It returns a {@link Rule},
 * itself a {@link RequestMatcher} rather than an unrelated builder type, whose default methods
 * finish the rule: <pre>
 * AuthorizedUrlMatcher.requestMatchers("/moduleServlet/myModule/admin/**").hasAuthority("Manage My Module")
 * </pre>
 * <p>
 * Deliberately not shaped like {@code HttpSecurity.authorizeHttpRequests(...)}, whose shared
 * registry allows {@code anyRequest()} only once and resolves overlaps first-registered-wins: a
 * module contributing there could crash startup or have its rule silently ignored. Each rule is
 * self-contained instead - an unmatched URL is permitted, and where several rules match, all must
 * agree, so the combination is never looser than its strictest rule (see
 * {@link OpenmrsAuthorizationManager}).
 *
 * @since 3.0.0
 */
public interface AuthorizedUrlMatcher {

	/**
	 * @return the {@link RequestMatcher} this rule governs
	 */
	RequestMatcher getRequestMatcher();

	/**
	 * @return the {@link AuthorizationManager} checked for a request matching
	 *         {@link #getRequestMatcher()}
	 */
	AuthorizationManager<RequestAuthorizationContext> getAuthorizationManager();

	/**
	 * @param patterns one or more {@code PathPattern} path patterns (e.g.
	 *            {@code "/moduleServlet/myModule/**"}), relative to the servlet context; a request
	 *            matches if any one of them does. Parsed by {@code PathPatternParser}, so {@code **}
	 *            may appear only once and only at the start or end of a pattern, and URI template
	 *            variables ({@code "/a/{id}/b"}) are supported
	 * @return a {@link Rule} for the given patterns, ready to be turned into a
	 *         {@link AuthorizedUrlMatcher} by naming the authorization check that governs it
	 */
	static Rule requestMatchers(String... patterns) {
		RequestMatcher matcher = (patterns.length == 1) ? PathPatternRequestMatcher.pathPattern(patterns[0])
		        : new OrRequestMatcher(Arrays.stream(patterns).map(PathPatternRequestMatcher::pathPattern).toList());
		return matcher::matches;
	}

	/**
	 * A {@link RequestMatcher} that can also be turned directly into a {@link AuthorizedUrlMatcher} by
	 * naming the authorization check that governs it. This is not a separate, unrelated builder type:
	 * {@link RequestMatcher} itself declares exactly one abstract method
	 * ({@link RequestMatcher#matches(jakarta.servlet.http.HttpServletRequest)}), so a sub-interface
	 * that only adds default methods remains a valid functional interface - the value returned by
	 * {@link #requestMatchers(String...)} genuinely is a {@link RequestMatcher}, usable anywhere one is
	 * expected, with these methods simply riding along.
	 */
	@FunctionalInterface
	interface Rule extends RequestMatcher {

		/**
		 * @return a rule granting anyone access, regardless of authentication
		 */
		default AuthorizedUrlMatcher permitAll() {
			return access(SingleResultAuthorizationManager.permitAll());
		}

		/**
		 * @return a rule denying everyone access
		 */
		default AuthorizedUrlMatcher denyAll() {
			return access(SingleResultAuthorizationManager.denyAll());
		}

		/**
		 * @param authority the privilege name required, resolved through
		 *            {@code Context.hasPrivilege(String)} (see {@link #factory()})
		 * @return a rule requiring the current user hold {@code authority}
		 */
		default AuthorizedUrlMatcher hasAuthority(String authority) {
			return access(factory().hasAuthority(authority));
		}

		/**
		 * @param authorities the privilege names, any one of which suffices
		 * @return a rule requiring the current user hold at least one of {@code authorities}
		 */
		default AuthorizedUrlMatcher hasAnyAuthority(String... authorities) {
			return access(factory().hasAnyAuthority(authorities));
		}

		/**
		 * @param authorities the privilege names, every one of which is required
		 * @return a rule requiring the current user hold every one of {@code authorities}
		 */
		default AuthorizedUrlMatcher hasAllAuthorities(String... authorities) {
			return access(factory().hasAllAuthorities(authorities));
		}

		/**
		 * @param role the role name required, with or without a {@code ROLE_} prefix, resolved through
		 *            {@code User#hasRole(String)} (see {@link #factory()})
		 * @return a rule requiring the current user hold {@code role}
		 */
		default AuthorizedUrlMatcher hasRole(String role) {
			return access(factory().hasRole(role));
		}

		/**
		 * @param roles the role names, with or without a {@code ROLE_} prefix, any one of which suffices
		 * @return a rule requiring the current user hold at least one of {@code roles}
		 */
		default AuthorizedUrlMatcher hasAnyRole(String... roles) {
			return access(factory().hasAnyRole(roles));
		}

		/**
		 * @param roles the role names, with or without a {@code ROLE_} prefix, every one of which is
		 *            required
		 * @return a rule requiring the current user hold every one of {@code roles}
		 */
		default AuthorizedUrlMatcher hasAllRoles(String... roles) {
			return access(factory().hasAllRoles(roles));
		}

		/**
		 * @return a rule requiring only that the caller be authenticated - the URL equivalent of a no-value
		 *         {@code @Authorized}, though see {@code OpenmrsPermissionEvaluator}'s javadoc (api module)
		 *         for why this and a no-value {@code @Authorized} still agree even though this uses
		 *         Spring's built-in {@code isAuthenticated()} semantics
		 */
		default AuthorizedUrlMatcher authenticated() {
			return access(AuthenticatedAuthorizationManager.authenticated());
		}

		/**
		 * @return the OpenMRS semantics behind the named checks above, shared with
		 *         {@code @PreAuthorize}/{@code @PostAuthorize} (see
		 *         {@code OpenmrsSecurityConfig#methodSecurityExpressionHandler}) so a privilege or role
		 *         name means the same thing whether it guards a URL or a service method. Built per call,
		 *         which happens while rules are being assembled at startup, not per request.
		 */
		private static OpenmrsAuthorizationManagerFactory<RequestAuthorizationContext> factory() {
			return new OpenmrsAuthorizationManagerFactory<>();
		}

		/**
		 * @param manager any {@link AuthorizationManager} - an escape hatch for anything the named
		 *            convenience methods above don't cover, such as
		 *            {@code (auth, ctx) -> new AuthorizationDecision(Context.hasPrivilege("X"))} for exact
		 *            {@code Context.hasPrivilege(String)} parity
		 * @return a rule requiring {@code manager} to grant access
		 */
		default AuthorizedUrlMatcher access(AuthorizationManager<RequestAuthorizationContext> manager) {
			RequestMatcher self = this;
			return new AuthorizedUrlMatcher() {

				@Override
				public RequestMatcher getRequestMatcher() {
					return self;
				}

				@Override
				public AuthorizationManager<RequestAuthorizationContext> getAuthorizationManager() {
					return manager;
				}
			};
		}
	}
}
