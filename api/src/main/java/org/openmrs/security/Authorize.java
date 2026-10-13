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

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.hibernate.proxy.HibernateProxy;
import org.openmrs.OpenmrsObject;
import org.openmrs.api.context.Context;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.aop.target.EmptyTargetSource;
import org.springframework.util.ClassUtils;

/**
 * Applies registered {@link DomainObjectAuthorizationRule}s to what a presentation layer is about
 * to serialize, replacing what a rule refuses with a {@link MaskedObject} rather than dropping it.
 * <p>
 * Service methods decide <em>whether</em> a call is allowed, and {@code @PostFilter} already drops
 * elements a rule refuses. This is for the layer after that: webservices.rest and the FHIR module
 * hold an object graph and have to decide how much of it to write out, and a reader needs to be
 * able to tell data that is hidden from data that does not exist. Masking says so; a shorter list
 * does not.
 * <p>
 * <strong>What comes back must never be written.</strong> A masked object is a serialization-time
 * artifact: it carries no data, and persisting one would blank the record it stands for. Handing
 * one to a {@code save*} method is rejected rather than attempted (see {@code RequiredDataAdvice}).
 * <p>
 * Every rule is asked about {@link #GET} rather than about a privilege the caller names. What is
 * being decided here is not whether the call was allowed - the service method settled that - but
 * how much of what it returned may be written out, and that is one question however the object was
 * reached.
 * <p>
 * <strong>Only the objects handed to these methods are checked.</strong> One a rule does not refuse
 * comes back exactly as it was, so nothing reachable through it is consulted either: a rule
 * covering {@code PersonAttribute} does nothing for {@code maskIfDenied(patient)}, and those
 * attributes go on to serialize in full. A refused object becomes a mask, which holds nothing, so
 * there is nothing below that to check. Either way no rule sees a nested object.
 * <p>
 * Reaching one means naming it: {@code maskIfDenied(patient.getAttributes())} as well as the
 * patient. A proxy that intercepted the getters instead would have to hold the real object to
 * delegate to, which inverts the fail-safe property of {@link #standInFor(OpenmrsObject)} - a
 * getter it failed to cover would return real data rather than nothing.
 *
 * @see MaskedObject
 * @see DomainObjectAuthorizationRule
 * @since 3.0.0
 */
public final class Authorize {

	/**
	 * First group of the uuid a mask reports, for a reader that has only the serialized value to go on
	 * and no {@link MaskedObject} to test. The remaining groups are random: see
	 * {@link #standInFor(OpenmrsObject)}.
	 * <p>
	 * Hex, because the whole value has to parse as a uuid and a readable word cannot: {@code m},
	 * {@code s} and {@code k} are not hex digits, so {@code masked-} and uuid syntax are mutually
	 * exclusive. This spells what the alphabet allows and is improbable as the opening group of a real
	 * one.
	 */
	public static final String MASKED_UUID_PREFIX = "effaced0-";

	/**
	 * The permission every rule is asked about here, standing for "this is being read at the
	 * presentation layer" rather than for any one service method's privilege.
	 * <p>
	 * Not a privilege a role holds, and never checked against one: {@code rulesAuthorize} puts it
	 * straight to the rules without consulting {@code Context.hasPrivilege}, because whether the call
	 * was allowed is a question the service method already answered. A rule that wants to distinguish
	 * reading from writing can branch on it; one that does not can ignore it.
	 */
	public static final String GET = "Get";

	/**
	 * Which of a type's methods can yield a domain object, derived on first sight and kept. A view is
	 * built per object written out and consulted per call, so this must not be a reflective scan each
	 * time; everything not in here goes straight to the real object.
	 */
	private static final Map<Class<?>, Set<Method>> maskableMethodsByClass = new ConcurrentHashMap<>();

	private Authorize() {
	}

	/**
	 * The object, or a {@link MaskedObject} standing in for it when a registered rule refuses it.
	 *
	 * @param object the object about to be serialized, may be null
	 * @param <T> the object's type
	 * @return {@code object} itself when no rule refuses it, otherwise a masked stand-in of the same
	 *         type; null stays null
	 */
	public static <T extends OpenmrsObject> T maskIfDenied(T object) {
		OpenmrsPermissionEvaluator evaluator = evaluator();
		if (object == null || !evaluator.hasRules()) {
			return object;
		}

		return evaluator.rulesAuthorize(object, GET) ? view(object) : standInFor(object);
	}

	/**
	 * The collection with every object a registered rule refuses replaced by a {@link MaskedObject}.
	 * <p>
	 * Replaced rather than removed, so the size a caller sees is the size the query found: a reader can
	 * tell six observations with two hidden from four observations, and a page of twenty stays a page
	 * of twenty. Returns a new list and never mutates the argument - unlike {@code @PostFilter}, which
	 * filters in place and is why a {@code @PostFilter}ed {@code @Cacheable} method has to key its
	 * cache by the caller.
	 *
	 * @param collection the objects about to be serialized, may be null
	 * @param <T> the element type
	 * @return a new collection of the same size, in the same order; null stays null
	 */
	public static <T extends OpenmrsObject> Collection<T> maskIfDenied(Collection<T> collection) {
		if (collection == null) {
			return null;
		}

		OpenmrsPermissionEvaluator evaluator = evaluator();
		if (!evaluator.hasRules()) {
			return collection;
		}

		List<T> masked = new ArrayList<>(collection.size());
		for (T element : collection) {
			masked.add(
			    element == null ? null : evaluator.rulesAuthorize(element, GET) ? view(element) : standInFor(element));
		}
		return masked;
	}

	/**
	 * @param object the object to test, may be null
	 * @return true if {@code object} stands in for one a rule refused
	 */
	public static boolean isMasked(Object object) {
		return object instanceof MaskedObject;
	}

	/**
	 * A view of {@code object}: the real object behind a proxy that answers every getter which can
	 * yield a domain object through {@link #maskIfDenied(OpenmrsObject)}, so a refused one comes back
	 * as a mask and an allowed one as a view of its own. Everything else goes straight through.
	 * <p>
	 * Already a mask or a view, so nothing to do: wrapping either again would stack proxies for no
	 * gain, and a mask holds nothing to look into.
	 */
	@SuppressWarnings("unchecked")
	private static <T extends OpenmrsObject> T view(T object) {
		if (object instanceof MaskedObject || object instanceof FieldMaskedObject) {
			return object;
		}

		Class<?> viewedType = targetTypeOf(object);
		Set<Method> maskable = maskableMethodsOf(viewedType);
		if (maskable.isEmpty()) {
			return object;
		}

		ProxyFactory factory = new ProxyFactory(object);
		factory.setProxyTargetClass(true);
		factory.addInterface(FieldMaskedObject.class);
		factory.addAdvice(new ViewInterceptor(viewedType, maskable));
		return (T) factory.getProxy(object.getClass().getClassLoader());
	}

	/**
	 * The no-argument methods of {@code type} whose return type could be a domain object, or a
	 * collection that might hold them. Decided from the declared return type, so a method that can
	 * never yield one is never intercepted and never has its value examined.
	 */
	private static Set<Method> maskableMethodsOf(Class<?> type) {
		return maskableMethodsByClass.computeIfAbsent(type, resolved -> {
			Set<Method> maskable = new HashSet<>();
			for (Method method : resolved.getMethods()) {
				if (method.getParameterCount() > 0) {
					continue;
				}
				Class<?> returnType = method.getReturnType();
				if (OpenmrsObject.class.isAssignableFrom(returnType) || Collection.class.isAssignableFrom(returnType)
				        || Map.class.isAssignableFrom(returnType)) {
					maskable.add(method);
				}
			}
			return Set.copyOf(maskable);
		});
	}

	/** The entity class behind a Hibernate or AOP proxy, so methods are read off the real type. */
	private static Class<?> targetTypeOf(Object object) {
		if (object instanceof HibernateProxy hibernateProxy) {
			return hibernateProxy.getHibernateLazyInitializer().getPersistentClass();
		}

		return ClassUtils.getUserClass(AopProxyUtils.ultimateTargetClass(object));
	}

	/**
	 * A stand-in of {@code object}'s own type, built with no target so that a method this mask does not
	 * recognize cannot reach the real object: the proxy has nothing to delegate to, and every call is
	 * answered by {@link MaskInterceptor}.
	 * <p>
	 * It discloses nothing of what it masks, its identity included. The uuid it reports is
	 * {@link #MASKED_UUID_PREFIX} followed by the remaining groups of a fresh random one, and its id is
	 * null, because the real identifiers are themselves disclosure: returning them from a search result
	 * would tell a caller that a record exists and hand over a key to try elsewhere. A substitute is
	 * reported rather than nothing because the layers downstream want one - fhir2's translators set a
	 * resource's {@code id} from the uuid, which a bundle entry's {@code fullUrl} is in turn built
	 * from, and a REST representation is keyed by uuid.
	 * <p>
	 * Generated once per mask, so it is stable while one object is being written out, and deliberately
	 * not derived from the real uuid, so it is stable for nothing else: two masks of the same record do
	 * not match. Correlating hidden entries across requests is not a capability this is meant to give.
	 * <p>
	 * Well-formed rather than a decorated string, so anything parsing it as a uuid - a client, a column
	 * of that type, {@link UUID#fromString(String)} - is not handed something it rejects. The random
	 * groups come from a version 4 uuid, so the version and variant bits are those of a real one.
	 */
	@SuppressWarnings("unchecked")
	private static <T extends OpenmrsObject> T standInFor(T object) {
		ProxyFactory factory = new ProxyFactory();
		factory.setTargetSource(EmptyTargetSource.forClass(object.getClass()));
		factory.setProxyTargetClass(true);
		factory.addInterface(MaskedObject.class);
		// substring(9) drops the random uuid's own first group and separator, so the result is still 36
		// characters in 8-4-4-4-12
		factory.addAdvice(
		    new MaskInterceptor(object.getClass(), MASKED_UUID_PREFIX + UUID.randomUUID().toString().substring(9)));
		return (T) factory.getProxy(object.getClass().getClassLoader());
	}

	private static OpenmrsPermissionEvaluator evaluator() {
		return Context.getRegisteredComponents(OpenmrsPermissionEvaluator.class).get(0);
	}

	/**
	 * Answers a view's domain-object getters through the rules and passes everything else straight to
	 * the real object.
	 * <p>
	 * Delegating is the default, which is the opposite of {@link MaskInterceptor}'s stance and the cost
	 * of holding a target at all: a getter whose return type hides a domain object - behind
	 * {@code Object}, or a raw collection this cannot see into - is not intercepted and returns real
	 * data. Service-level authorization, not this, is what stands between a caller and data they may
	 * not have.
	 */
	private static final class ViewInterceptor implements MethodInterceptor {

		private final Class<?> viewedType;

		private final Set<Method> maskable;

		private ViewInterceptor(Class<?> viewedType, Set<Method> maskable) {
			this.viewedType = viewedType;
			this.maskable = maskable;
		}

		@Override
		@SuppressWarnings("unchecked")
		public Object invoke(MethodInvocation invocation) throws Throwable {
			if ("getViewedType".equals(invocation.getMethod().getName())) {
				return viewedType;
			}

			Object value = invocation.proceed();
			if (value == null || !maskable.contains(invocation.getMethod())) {
				return value;
			}

			if (value instanceof OpenmrsObject child) {
				return maskIfDenied(child);
			}
			if (value instanceof Collection<?> elements) {
				return maskedCollection(elements, invocation.getMethod().getReturnType());
			}
			if (value instanceof Map<?, ?> entries) {
				return maskedValues(entries);
			}
			return value;
		}

		/**
		 * The collection with its elements judged, in a type the getter's declared return accepts. An
		 * {@link ArrayList} where a {@link Set} was declared fails the generated method's cast, which is
		 * how {@code Person.getAddresses()} broke a REST Patient conversion: the exception surfaced from
		 * the proxy rather than from anything that looked related.
		 * <p>
		 * Left alone when any element is not a domain object, since there is nothing to ask a rule about
		 * and the original is the only thing guaranteed to fit.
		 */
		@SuppressWarnings("unchecked")
		private static Object maskedCollection(Collection<?> elements, Class<?> declaredType) {
			if (!elements.stream().allMatch(element -> element == null || element instanceof OpenmrsObject)) {
				return elements;
			}

			Collection<OpenmrsObject> masked = maskIfDenied((Collection<OpenmrsObject>) elements);
			return Set.class.isAssignableFrom(declaredType) ? new LinkedHashSet<>(masked) : new ArrayList<>(masked);
		}

		/**
		 * The map with its domain-object values judged and its keys untouched - {@code Person}'s attribute
		 * maps are keyed by name, and masking a key would break every lookup against the map it is handed
		 * back in.
		 */
		private static Object maskedValues(Map<?, ?> entries) {
			Map<Object, Object> masked = new LinkedHashMap<>(entries.size());
			entries.forEach(
			    (key, value) -> masked.put(key, value instanceof OpenmrsObject child ? maskIfDenied(child) : value));
			return masked;
		}
	}

	/**
	 * Answers every call on a masked object without a target to fall back on, so a getter nobody
	 * thought about returns emptiness rather than data. Collection, map and array returns come back
	 * empty rather than null, because a serializer handed a null where it expected a collection fails
	 * on the response it was halfway through writing.
	 * <p>
	 * A setter throws. Masking is for a read on its way out, and writing to one is a programmer error
	 * worth hearing about at the call site rather than when the blanked record reaches the database.
	 */
	private static final class MaskInterceptor implements MethodInterceptor {

		private final Class<?> maskedType;

		private final String uuid;

		private MaskInterceptor(Class<?> maskedType, String uuid) {
			this.maskedType = maskedType;
			this.uuid = uuid;
		}

		@Override
		public Object invoke(MethodInvocation invocation) {
			Method method = invocation.getMethod();
			String name = method.getName();

			switch (name) {
				case "getMaskedType":
					return maskedType;
				case "getUuid":
					return uuid;
				case "toString":
					return "masked " + maskedType.getName() + "[" + uuid + "]";
				case "hashCode":
					return System.identityHashCode(invocation.getThis());
				case "equals":
					return invocation.getThis() == invocation.getArguments()[0];
				default:
					break;
			}

			if (name.startsWith("set") && method.getParameterCount() == 1) {
				throw new UnsupportedOperationException(
				        "Cannot write to a masked " + maskedType.getName() + ": it stands in for an object the "
				                + "current user may not read, and persisting it would blank that record");
			}

			return emptyValueFor(method.getReturnType());
		}

		private static Object emptyValueFor(Class<?> returnType) {
			if (Set.class.isAssignableFrom(returnType)) {
				return Collections.emptySet();
			}
			if (Map.class.isAssignableFrom(returnType)) {
				return Collections.emptyMap();
			}
			if (Collection.class.isAssignableFrom(returnType)) {
				return Collections.emptyList();
			}
			if (returnType.isArray()) {
				return Array.newInstance(returnType.getComponentType(), 0);
			}
			if (Boolean.class.equals(returnType)) {
				// boxed, but treated as a flag everywhere in the domain model: `if (x.getVoided())` is the
				// common idiom, so a null here would NPE the very serialization this is for
				return Boolean.FALSE;
			}
			if (returnType.isPrimitive() && !void.class.equals(returnType)) {
				// the zero value of any primitive, boxed: a one-element array of it is zero-filled, so this
				// covers false and '\0' as well as the numeric zeroes without a branch each
				return Array.get(Array.newInstance(returnType, 1), 0);
			}
			return null;
		}
	}
}
