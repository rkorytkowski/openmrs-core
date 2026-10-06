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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.openmrs.api.context.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.SimpleMethodInvocation;

/**
 * Enforces a privilege from inside a domain object's getter, for data that needs a privilege of its
 * own rather than the one guarding the service method that returned the object - e.g.
 * {@code Obs#getOrder()} requiring {@code Get Orders}.
 * <p>
 * {@link #requirePrivilege(String)} takes a privilege name, and {@link #require(String, Object)} a
 * SpEL expression in the same vocabulary as {@code @PreAuthorize} - see that method for which to
 * pick. Both have a counterpart returning {@code null} rather than denying, and
 * {@link #filter(String, Object, Set)} drops the elements of a collection the caller may not see,
 * as {@code @PostFilter} does.
 * <p>
 * Done in the getter rather than with {@code @AuthorizeReturnObject} because that returns a proxy,
 * and a proxied entity loses reference and {@code equals} identity, is rejected by Hibernate when
 * it reaches a cascade, and is invisible to the field-reflective cascade machinery in
 * {@code RequiredDataAdvice}.
 * <p>
 * A guarded property must be mapped with {@code access="field"} so Hibernate reads the field rather
 * than the guarded getter; otherwise loading or flushing the entity would depend on the current
 * user's privileges.
 *
 * @since 3.0.0
 */
public final class Authorize {

	private static final Logger log = LoggerFactory.getLogger(Authorize.class);

	/**
	 * Parsing a SpEL expression costs far more than evaluating one, and {@code @PreAuthorize} pays it
	 * once per method at proxy creation. Keyed by the expression, which comes from source, so the map
	 * is bounded by the number of guarded getters.
	 */
	private static final Map<String, Expression> EXPRESSIONS = new ConcurrentHashMap<>();

	/**
	 * Stands in for the getter being guarded. The expression handler builds its root object from a
	 * {@link org.aopalliance.intercept.MethodInvocation}, and uses the method only to name the
	 * arguments as {@code #param} variables - which a getter has none of, {@code #target} being set
	 * directly instead.
	 */
	private static final Method GUARDED_READ;

	static {
		try {
			GUARDED_READ = Authorize.class.getDeclaredMethod("guardedRead");
		} catch (NoSuchMethodException e) {
			throw new IllegalStateException(e);
		}
	}

	private Authorize() {
	}

	private static void guardedRead() {
	}

	/**
	 * @throws AuthorizationDeniedException naming {@code privilege} if the current user lacks it
	 */
	public static void requirePrivilege(String privilege) {
		if (!permitted(privilege)) {
			throw new AuthorizationDeniedException(denialMessage(privilege));
		}
	}

	/**
	 * @return {@code value} if the current user holds {@code privilege}, otherwise {@code null} - for
	 *         data that is better omitted than fatal, such as a field being serialized for display
	 */
	public static <T> T maskPrivilege(String privilege, T value) {
		return permitted(privilege) ? value : null;
	}

	/**
	 * @see #require(String, Object)
	 */
	public static void require(String expression) {
		require(expression, null);
	}

	/**
	 * Enforces a SpEL expression evaluated by the same {@code MethodSecurityExpressionHandler} as
	 * {@code @PreAuthorize} (see {@code OpenmrsSecurityConfig#methodSecurityExpressionHandler}), so
	 * {@code hasAuthority}, {@code hasAnyAuthority}, {@code hasRole}, {@code isAuthenticated} and
	 * {@code hasPermission} - including rules a module contributes - mean exactly what they do in an
	 * annotation. Use it for anything the plain privilege name cannot say, and
	 * {@link #requirePrivilege(String)} otherwise: a getter can be called in a tight loop, and
	 * evaluating an expression costs substantially more than comparing a privilege name.
	 * <p>
	 * Unlike an annotation there is no method signature to draw variables from, so the expression sees
	 * {@code #target} rather than named parameters.
	 *
	 * @param expression a SpEL expression, e.g. {@code "hasPermission(#target, 'Get Orders')"}
	 * @param target the object whose getter is running, bound to {@code #target}; may be
	 *            <code>null</code> for an expression that does not need it
	 * @throws AuthorizationDeniedException naming the privileges the expression found missing
	 * @throws IllegalArgumentException if {@code expression} is not parseable - a privilege name passed
	 *             here by mistake is the likely cause
	 */
	public static void require(String expression, Object target) {
		require(expression, target, null);
	}

	/**
	 * The denying counterpart of {@link #mask(String, Object, Object)}, for a guard whose rule is about
	 * the value rather than the object holding it: {@code value} is bound as {@code returnObject}, as
	 * under {@code @PostAuthorize}, so {@code hasPermission(returnObject, 'Get Orders')} reaches a
	 * module's {@link DomainObjectAuthorizationRule} for the returned type rather than for the holder.
	 *
	 * @param value the value the getter is about to return, bound to {@code returnObject}; a
	 *            <code>null</code> one is not bound, leaving {@code returnObject} null - which
	 *            {@code hasPermission} answers on the privilege alone, there being no object to decide
	 *            about
	 * @see #require(String, Object)
	 */
	public static void require(String expression, Object target, Object value) {
		MethodSecurityExpressionHandler handler = handler();
		if (handler == null) {
			return;
		}

		Set<String> enclosing = MissingPrivilegeRecorder.begin();
		boolean granted;
		Set<String> missingPrivileges;
		try {
			granted = evaluate(handler, expression, target, value);
		} finally {
			missingPrivileges = MissingPrivilegeRecorder.end(enclosing);
		}

		if (!granted) {
			// named the same way PrivilegeNamingAuthorizationManager names an annotation's denial
			throw new AuthorizationDeniedException(missingPrivileges.isEmpty() ? "Access is denied by " + expression
			        : denialMessage(String.join(",", missingPrivileges)));
		}
	}

	/**
	 * The {@link #maskPrivilege(String, Object)} counterpart of {@link #require(String, Object)}. The
	 * value is bound as {@code returnObject}, as under {@code @PostAuthorize}, so an expression can
	 * check the value itself rather than its holder.
	 *
	 * @return {@code value} if {@code expression} grants access, otherwise {@code null}
	 */
	public static <T> T mask(String expression, Object target, T value) {
		MethodSecurityExpressionHandler handler = handler();
		if (handler == null) {
			return value;
		}

		Set<String> enclosing = MissingPrivilegeRecorder.begin();
		try {
			return evaluate(handler, expression, target, value) ? value : null;
		} finally {
			MissingPrivilegeRecorder.end(enclosing);
		}
	}

	/**
	 * The {@code @PostFilter} counterpart: keeps the elements {@code expression} grants, with each
	 * bound to {@code filterObject} in turn, exactly as an annotation evaluates it.
	 * <p>
	 * Returns a copy and never touches {@code values}, which is the difference that matters in a
	 * getter. A service method filters a fresh query result, but a getter hands back the entity's own
	 * collection, and Spring filters a collection by clearing it and adding back what survived - on a
	 * persistent collection that is a dissociation, written out at the next flush, deleting rows for a
	 * {@code cascade="all-delete-orphan"} association. A filtered getter therefore has to be documented
	 * as returning a copy, since a caller cannot mutate it to add to the entity, and the copy also
	 * initializes a lazy collection in full.
	 * <p>
	 * Machinery that saves, voids, validates or copies the collection rather than showing it must read
	 * past the filter - through the field, or an unfiltered accessor where it sits outside the entity,
	 * as {@code Obs.getNoAuthGroupMembers(boolean)} is for the obs services and validator. Otherwise an
	 * element the caller cannot see is quietly left out of the write.
	 * <p>
	 * Per-element decisions need a {@link DomainObjectAuthorizationRule} for the element type that
	 * discriminates between instances, typically through
	 * {@code hasPermission(filterObject, 'Some Privilege')}. Without one, {@code hasPermission} falls
	 * back to a plain privilege check, which is the same answer for every element and so keeps all of
	 * them or none - no better than {@link #maskPrivilege(String, Object)} returning an empty
	 * collection. There is no privilege-name overload for that reason.
	 *
	 * @param expression a SpEL expression over {@code filterObject}, e.g.
	 *            {@code "hasPermission(filterObject, 'Get Orders')"}
	 * @param target the object whose getter is running, bound to {@code #target}
	 * @param values the entity's collection, left untouched; <code>null</code> and empty are returned
	 *            as they are
	 * @return a new {@link Set} holding the elements that were granted, in iteration order
	 */
	public static <T> Set<T> filter(String expression, Object target, Set<T> values) {
		MethodSecurityExpressionHandler handler = filteringHandler(values);
		return handler == null ? values : filtered(handler, expression, target, new LinkedHashSet<>(values));
	}

	/**
	 * @see #filter(String, Object, Set)
	 */
	public static <T> List<T> filter(String expression, Object target, List<T> values) {
		MethodSecurityExpressionHandler handler = filteringHandler(values);
		return handler == null ? values : filtered(handler, expression, target, new ArrayList<>(values));
	}

	/**
	 * @see #filter(String, Object, Set)
	 */
	public static <T> Collection<T> filter(String expression, Object target, Collection<T> values) {
		MethodSecurityExpressionHandler handler = filteringHandler(values);
		return handler == null ? values : filtered(handler, expression, target, new ArrayList<>(values));
	}

	/**
	 * @param copy a mutable copy of the caller's collection, so Spring's own filtering - which clears
	 *            the collection and adds back what survived - mutates and returns this and not the
	 *            entity's own
	 */
	private static <T, C extends Collection<T>> C filtered(MethodSecurityExpressionHandler handler, String expression,
	        Object target, C copy) {
		EvaluationContext context = evaluationContext(handler, target, null);

		Set<String> enclosing = MissingPrivilegeRecorder.begin();
		try {
			handler.filter(copy, parsed(expression, handler), context);
			return copy;
		} finally {
			MissingPrivilegeRecorder.end(enclosing);
		}
	}

	/**
	 * @return <code>null</code> when the collection cannot or need not be filtered - nothing to check
	 *         against (see {@link #handler()}), or nothing to filter, an empty collection costing an
	 *         evaluation context to come back empty
	 */
	private static MethodSecurityExpressionHandler filteringHandler(Collection<?> values) {
		return (values == null || values.isEmpty()) ? null : handler();
	}

	private static boolean evaluate(MethodSecurityExpressionHandler handler, String expression, Object target,
	        Object value) {
		EvaluationContext context = evaluationContext(handler, target, value);

		return Boolean.TRUE.equals(parsed(expression, handler).getValue(context, Boolean.class));
	}

	/**
	 * @return the handler, or <code>null</code> when there is nothing to evaluate against: no session,
	 *         so no caller identity, or no application context to resolve the handler from. The latter
	 *         is not reachable in a running OpenMRS - the context is what starts it - but a domain
	 *         object still has to work as a plain bean in a unit test holding only a
	 *         {@code UserContext}, and denying there would make a guarded getter unusable rather than
	 *         more secure.
	 */
	private static MethodSecurityExpressionHandler handler() {
		if (!Context.isSessionOpen()) {
			return null;
		}
		try {
			return Context.getRegisteredComponent("methodSecurityExpressionHandler", MethodSecurityExpressionHandler.class);
		} catch (RuntimeException e) {
			log.debug("No application context, so '{}' cannot be evaluated and the read is permitted",
			    MethodSecurityExpressionHandler.class.getSimpleName(), e);
			return null;
		}
	}

	private static EvaluationContext evaluationContext(MethodSecurityExpressionHandler handler, Object target,
	        Object value) {
		EvaluationContext context = handler.createEvaluationContext(
		    () -> SecurityContextHolder.getContext().getAuthentication(), new SimpleMethodInvocation(target, GUARDED_READ));
		context.setVariable("target", target);
		if (value != null) {
			handler.setReturnObject(value, context);
		}
		return context;
	}

	private static Expression parsed(String expression, MethodSecurityExpressionHandler handler) {
		return EXPRESSIONS.computeIfAbsent(expression, candidate -> {
			try {
				return handler.getExpressionParser().parseExpression(candidate);
			} catch (ParseException e) {
				throw new IllegalArgumentException("Not a SpEL expression: '" + candidate
				        + "'. A privilege name belongs in Authorize.requirePrivilege(String) instead.", e);
			}
		});
	}

	/**
	 * Permits the read when no session is open: there is no {@link org.openmrs.api.context.UserContext}
	 * to check, so there is no caller identity to withhold the value from, and whatever holds the
	 * object already has it in hand. Enforcing instead would make a domain object unusable as a plain
	 * bean outside a session - including to every reflective property walker, which reads all getters.
	 */
	private static boolean permitted(String privilege) {
		return !Context.isSessionOpen() || PrivilegeResolution.holdsPrivilege(privilege);
	}

	private static String denialMessage(String privileges) {
		return Context.getMessageSourceService().getMessage("error.privilegesRequired", new Object[] { privileges },
		    Locale.getDefault());
	}
}
