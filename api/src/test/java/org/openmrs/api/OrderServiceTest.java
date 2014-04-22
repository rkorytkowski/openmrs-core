/**
 * The contents of this file are subject to the OpenMRS Public License
 * Version 1.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://license.openmrs.org
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * Copyright (C) OpenMRS, LLC.  All Rights Reserved.
 */
package org.openmrs.api;

import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.openmrs.test.TestUtil.containsId;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.openmrs.CareSetting;
import org.openmrs.Concept;
import org.openmrs.ConceptClass;
import org.openmrs.ConceptName;
import org.openmrs.DraftDrugOrder;
import org.openmrs.Drug;
import org.openmrs.DrugOrder;
import org.openmrs.Encounter;
import org.openmrs.GlobalProperty;
import org.openmrs.Obs;
import org.openmrs.Order;
import org.openmrs.Order.Action;
import org.openmrs.OrderFrequency;
import org.openmrs.OrderType;
import org.openmrs.Patient;
import org.openmrs.Provider;
import org.openmrs.TestOrder;
import org.openmrs.api.context.Context;
import org.openmrs.order.OrderUtil;
import org.openmrs.order.OrderUtilTest;
import org.openmrs.orders.TimestampOrderNumberGenerator;
import org.openmrs.test.BaseContextSensitiveTest;
import org.openmrs.test.TestUtil;
import org.openmrs.test.Verifies;
import org.openmrs.util.OpenmrsConstants;
import org.openmrs.util.PrivilegeConstants;

/**
 * TODO clean up and test all methods in OrderService
 */
public class OrderServiceTest extends BaseContextSensitiveTest {
	
	private static final String OTHER_ORDER_FREQUENCIES_XML = "org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml";
	
	private ConceptService conceptService;
	
	private OrderService orderService;
	
	private PatientService patientService;
	
	private EncounterService encounterService;
	
	private ProviderService providerService;
	
	@Rule
	public ExpectedException expectedException = ExpectedException.none();
	
	private class SomeTestOrder extends TestOrder {}
	
	@Before
	public void setup() {
		if (orderService == null) {
			orderService = Context.getOrderService();
		}
		if (patientService == null) {
			patientService = Context.getPatientService();
		}
		
		if (conceptService == null) {
			conceptService = Context.getConceptService();
		}
		
		if (encounterService == null) {
			encounterService = Context.getEncounterService();
		}
		if (providerService == null) {
			providerService = Context.getProviderService();
		}
	}
	
	/**
	 * @see {@link OrderService#saveOrder(org.openmrs.Order, OrderContext)}
	 */
	@Test(expected = APIException.class)
	@Verifies(value = "should not save order if order doesnt validate", method = "saveOrder(Order)")
	public void saveOrder_shouldNotSaveOrderIfOrderDoesntValidate() throws Exception {
		OrderService orderService = Context.getOrderService();
		Order order = new Order();
		order.setPatient(null);
		order.setOrderer(null);
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @see {@link OrderService#getOrderByUuid(String)}
	 */
	@Test
	@Verifies(value = "should find object given valid uuid", method = "getOrderByUuid(String)")
	public void getOrderByUuid_shouldFindObjectGivenValidUuid() throws Exception {
		String uuid = "921de0a3-05c4-444a-be03-e01b4c4b9142";
		Order order = Context.getOrderService().getOrderByUuid(uuid);
		Assert.assertEquals(1, (int) order.getOrderId());
	}
	
	/**
	 * @see {@link OrderService#getOrderByUuid(String)}
	 */
	@Test
	@Verifies(value = "should return null if no object found with given uuid", method = "getOrderByUuid(String)")
	public void getOrderByUuid_shouldReturnNullIfNoObjectFoundWithGivenUuid() throws Exception {
		Assert.assertNull(Context.getOrderService().getOrderByUuid("some invalid uuid"));
	}
	
	@Test
	public void purgeOrder_shouldDeleteObsThatReference() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-deleteObsThatReference.xml");
		final String ordUuid = "0c96f25c-4949-4f72-9931-d808fbcdb612";
		final String obsUuid = "be3a4d7a-f9ab-47bb-aaad-bc0b452fcda4";
		ObsService os = Context.getObsService();
		OrderService service = Context.getOrderService();
		
		Obs obs = os.getObsByUuid(obsUuid);
		Assert.assertNotNull(obs);
		
		Order order = service.getOrderByUuid(ordUuid);
		Assert.assertNotNull(order);
		
		//sanity check to ensure that the obs and order are actually related
		Assert.assertEquals(order, obs.getOrder());
		
		//Ensure that passing false does not delete the related obs
		service.purgeOrder(order, false);
		Assert.assertNotNull(os.getObsByUuid(obsUuid));
		
		service.purgeOrder(order, true);
		
		//Ensure that actually the order got purged
		Assert.assertNull(service.getOrderByUuid(ordUuid));
		
		//Ensure that the related obs got deleted
		Assert.assertNull(os.getObsByUuid(obsUuid));
		
	}
	
	/**
	 * @see {@link OrderNumberGenerator#getNewOrderNumber(OrderContext)}
	 */
	@Test
	@Verifies(value = "should always return unique orderNumbers when called multiple times without saving orders", method = "getNewOrderNumber()")
	public void getNewOrderNumber_shouldAlwaysReturnUniqueOrderNumbersWhenCalledMultipleTimesWithoutSavingOrders()
	        throws Exception {
		
		int N = 50;
		final Set<String> uniqueOrderNumbers = new HashSet<String>(50);
		List<Thread> threads = new ArrayList<Thread>();
		for (int i = 0; i < N; i++) {
			threads.add(new Thread(new Runnable() {
				
				@Override
				public void run() {
					try {
						Context.openSession();
						Context.addProxyPrivilege(PrivilegeConstants.ADD_ORDERS);
						uniqueOrderNumbers.add(((OrderNumberGenerator) Context.getOrderService()).getNewOrderNumber(null));
					}
					finally {
						Context.removeProxyPrivilege(PrivilegeConstants.ADD_ORDERS);
						Context.closeSession();
					}
				}
			}));
		}
		for (int i = 0; i < N; ++i) {
			threads.get(i).start();
		}
		for (int i = 0; i < N; ++i) {
			threads.get(i).join();
		}
		//since we used a set we should have the size as N indicating that there were no duplicates
		Assert.assertEquals(N, uniqueOrderNumbers.size());
	}
	
	/**
	 * @see {@link OrderService#getOrderByOrderNumber(String)}
	 */
	@Test
	@Verifies(value = "should find object given valid order number", method = "getOrderByOrderNumber(String)")
	public void getOrderByOrderNumber_shouldFindObjectGivenValidOrderNumber() throws Exception {
		Order order = Context.getOrderService().getOrderByOrderNumber("1");
		Assert.assertNotNull(order);
		Assert.assertEquals(1, (int) order.getOrderId());
	}
	
	/**
	 * @see {@link OrderService#getOrderByOrderNumber(String)}
	 */
	@Test
	@Verifies(value = "should return null if no object found with given order number", method = "getOrderByOrderNumber(String)")
	public void getOrderByOrderNumber_shouldReturnNullIfNoObjectFoundWithGivenOrderNumber() throws Exception {
		Assert.assertNull(Context.getOrderService().getOrderByOrderNumber("some invalid order number"));
	}
	
	/**
	 * @see {@link OrderService#getOrderHistoryByConcept(Patient,Concept)}
	 */
	@Test
	@Verifies(value = "should return orders with the given concept", method = "getOrderHistoryByConcept(Patient,Concept)")
	public void getOrderHistoryByConcept_shouldReturnOrdersWithTheGivenConcept() throws Exception {
		//We should have two orders with this concept.
		Concept concept = Context.getConceptService().getConcept(88);
		Patient patient = Context.getPatientService().getPatient(2);
		List<Order> orders = Context.getOrderService().getOrderHistoryByConcept(patient, concept);
		
		//They must be sorted by startDate starting with the latest
		Assert.assertEquals(4, orders.size());
		Assert.assertEquals(5, orders.get(0).getOrderId().intValue());
		Assert.assertEquals(444, orders.get(1).getOrderId().intValue());
		Assert.assertEquals(44, orders.get(2).getOrderId().intValue());
		Assert.assertEquals(4, orders.get(3).getOrderId().intValue());
		
		concept = Context.getConceptService().getConcept(792);
		orders = Context.getOrderService().getOrderHistoryByConcept(patient, concept);
		
		//They must be sorted by startDate starting with the latest
		Assert.assertEquals(4, orders.size());
		Assert.assertEquals(3, orders.get(0).getOrderId().intValue());
		Assert.assertEquals(222, orders.get(1).getOrderId().intValue());
		Assert.assertEquals(22, orders.get(2).getOrderId().intValue());
		Assert.assertEquals(2, orders.get(3).getOrderId().intValue());
	}
	
	/**
	 * @see {@link OrderService#getOrderHistoryByConcept(Patient, Concept)}
	 */
	@Test
	@Verifies(value = "should return empty list for concept without orders", method = "getOrderHistoryByConcept(Patient,Concept)")
	public void getOrderHistoryByConcept_shouldReturnEmptyListForConceptWithoutOrders() throws Exception {
		Concept concept = Context.getConceptService().getConcept(21);
		Patient patient = Context.getPatientService().getPatient(2);
		List<Order> orders = Context.getOrderService().getOrderHistoryByConcept(patient, concept);
		Assert.assertEquals(0, orders.size());
	}
	
	/**
	 * @verifies reject a null concept
	 * @see OrderService#getOrderHistoryByConcept(org.openmrs.Patient, org.openmrs.Concept)
	 */
	@Test(expected = IllegalArgumentException.class)
	public void getOrderHistoryByConcept_shouldRejectANullConcept() throws Exception {
		orderService.getOrderHistoryByConcept(new Patient(), null);
	}
	
	/**
	 * @verifies reject a null patient
	 * @see OrderService#getOrderHistoryByConcept(org.openmrs.Patient, org.openmrs.Concept)
	 */
	@Test(expected = IllegalArgumentException.class)
	public void getOrderHistoryByConcept_shouldRejectANullPatient() throws Exception {
		orderService.getOrderHistoryByConcept(null, new Concept());
	}
	
	/**
	 * @see {@link OrderService#getOrderHistoryByOrderNumber(String)}
	 */
	@Test
	@Verifies(value = "should return all order history for given order number", method = "getOrderHistoryByOrderNumber(String)")
	public void getOrderHistoryByOrderNumber_shouldReturnAllOrderHistoryForGivenOrderNumber() throws Exception {
		List<Order> orders = Context.getOrderService().getOrderHistoryByOrderNumber("111");
		assertEquals(2, orders.size());
		assertEquals(111, orders.get(0).getOrderId().intValue());
		assertEquals(1, orders.get(1).getOrderId().intValue());
	}
	
	/**
	 * @verifies return the order frequency that matches the specified id
	 * @see OrderService#getOrderFrequency(Integer)
	 */
	@Test
	public void getOrderFrequency_shouldReturnTheOrderFrequencyThatMatchesTheSpecifiedId() throws Exception {
		assertEquals("28090760-7c38-11e3-baa7-0800200c9a66", Context.getOrderService().getOrderFrequency(1).getUuid());
	}
	
	/**
	 * @verifies return the order frequency that matches the specified uuid
	 * @see OrderService#getOrderFrequencyByUuid(String)
	 */
	@Test
	public void getOrderFrequencyByUuid_shouldReturnTheOrderFrequencyThatMatchesTheSpecifiedUuid() throws Exception {
		assertEquals(1, Context.getOrderService().getOrderFrequencyByUuid("28090760-7c38-11e3-baa7-0800200c9a66")
		        .getOrderFrequencyId().intValue());
	}
	
	/**
	 * @verifies return only non retired order frequencies if includeRetired is set to false
	 * @see OrderService#getOrderFrequencies(boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldReturnOnlyNonRetiredOrderFrequenciesIfIncludeRetiredIsSetToFalse()
	        throws Exception {
		List<OrderFrequency> orderFrequencies = Context.getOrderService().getOrderFrequencies(false);
		assertEquals(2, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 1));
		assertTrue(containsId(orderFrequencies, 2));
	}
	
	/**
	 * @verifies return all the order frequencies if includeRetired is set to true
	 * @see OrderService#getOrderFrequencies(boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldReturnAllTheOrderFrequenciesIfIncludeRetiredIsSetToTrue() throws Exception {
		List<OrderFrequency> orderFrequencies = Context.getOrderService().getOrderFrequencies(true);
		assertEquals(3, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 1));
		assertTrue(containsId(orderFrequencies, 2));
		assertTrue(containsId(orderFrequencies, 3));
	}
	
	/**
	 * @verifies return all active orders for the specified patient
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnAllActiveOrdersForTheSpecifiedPatient() throws Exception {
		Patient patient = Context.getPatientService().getPatient(2);
		List<Order> orders = orderService.getActiveOrders(patient, null, null, null);
		assertEquals(5, orders.size());
		Order[] expectedOrders = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5), orderService.getOrder(7) };
		assertThat(orders, hasItems(expectedOrders));
		
		assertTrue(OrderUtilTest.isActiveOrder(orders.get(0), null));
		assertTrue(OrderUtilTest.isActiveOrder(orders.get(1), null));
		assertTrue(OrderUtilTest.isActiveOrder(orders.get(2), null));
		assertTrue(OrderUtilTest.isActiveOrder(orders.get(3), null));
		assertTrue(OrderUtilTest.isActiveOrder(orders.get(4), null));
	}
	
	/**
	 * @verifies return all active orders for the specified patient and care setting
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnAllActiveOrdersForTheSpecifiedPatientAndCareSetting() throws Exception {
		Patient patient = patientService.getPatient(2);
		CareSetting careSetting = orderService.getCareSetting(1);
		List<Order> orders = orderService.getActiveOrders(patient, null, careSetting, null);
		assertEquals(4, orders.size());
		Order[] expectedOrders = { orderService.getOrder(3), orderService.getOrder(444), orderService.getOrder(5),
		        orderService.getOrder(7) };
		assertThat(orders, hasItems(expectedOrders));
	}
	
	/**
	 * @verifies return all active drug orders for the specified patient
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnAllActiveDrugOrdersForTheSpecifiedPatient() throws Exception {
		Patient patient = patientService.getPatient(2);
		List<Order> orders = orderService.getActiveOrders(patient, orderService.getOrderType(1), null, null);
		assertEquals(4, orders.size());
		Order[] expectedOrders = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5) };
		assertThat(orders, hasItems(expectedOrders));
	}
	
	/**
	 * @verifies return all active test orders for the specified patient
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnAllActiveTestOrdersForTheSpecifiedPatient() throws Exception {
		Patient patient = patientService.getPatient(2);
		List<Order> orders = orderService
		        .getActiveOrders(patient, orderService.getOrderTypeByName("Test order"), null, null);
		assertEquals(1, orders.size());
		assertEquals(orders.get(0), orderService.getOrder(7));
	}
	
	/**
	 * @verifies fail if patient is null
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test(expected = IllegalArgumentException.class)
	public void getActiveOrders_shouldFailIfPatientIsNull() throws Exception {
		orderService.getActiveOrders(null, null, orderService.getCareSetting(1), null);
	}
	
	/**
	 * @verifies return active orders as of the specified date
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnActiveOrdersAsOfTheSpecifiedDate() throws Exception {
		Patient patient = Context.getPatientService().getPatient(2);
		List<Order> orders = orderService.getAllOrdersByPatient(patient);
		assertEquals(12, orders.size());
		
		Date asOfDate = Context.getDateFormat().parse("10/12/2007");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(9, orders.size());
		assertFalse(orders.contains(orderService.getOrder(22)));//DC
		assertFalse(orders.contains(orderService.getOrder(44)));//DC
		assertFalse(orders.contains(orderService.getOrder(8)));//voided
		
		Order[] expectedOrders = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(4),
		        orderService.getOrder(444), orderService.getOrder(5), orderService.getOrder(6), orderService.getOrder(7),
		        orderService.getOrder(9) };
		
		asOfDate = Context.getDateTimeFormat().parse("10/12/2007 00:01:00");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(8, orders.size());
		assertThat(orders, hasItems(expectedOrders));
		
		asOfDate = Context.getDateFormat().parse("10/04/2008");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(8, orders.size());
		assertThat(orders, hasItems(expectedOrders));
		
		asOfDate = Context.getDateTimeFormat().parse("10/04/2008 00:01:00");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(7, orders.size());
		Order[] expectedOrders1 = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5), orderService.getOrder(6), orderService.getOrder(7), orderService.getOrder(9) };
		assertThat(orders, hasItems(expectedOrders1));
		
		asOfDate = Context.getDateTimeFormat().parse("26/09/2008 09:24:10");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(7, orders.size());
		assertThat(orders, hasItems(expectedOrders1));
		
		asOfDate = Context.getDateTimeFormat().parse("26/09/2008 09:25:10");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(6, orders.size());
		Order[] expectedOrders2 = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5), orderService.getOrder(7), orderService.getOrder(9) };
		assertThat(orders, hasItems(expectedOrders2));
		
		asOfDate = Context.getDateFormat().parse("04/12/2008");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(5, orders.size());
		Order[] expectedOrders3 = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5), orderService.getOrder(7) };
		assertThat(orders, hasItems(expectedOrders3));
		
		asOfDate = Context.getDateFormat().parse("06/12/2008");
		orders = orderService.getActiveOrders(patient, null, null, asOfDate);
		assertEquals(5, orders.size());
		assertThat(orders, hasItems(expectedOrders3));
	}
	
	/**
	 * @verifies return all orders if no orderType is specified
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldReturnAllOrdersIfNoOrderTypeIsSpecified() throws Exception {
		Patient patient = Context.getPatientService().getPatient(2);
		List<Order> orders = orderService.getActiveOrders(patient, null, null, null);
		assertEquals(5, orders.size());
		Order[] expectedOrders = { orderService.getOrder(222), orderService.getOrder(3), orderService.getOrder(444),
		        orderService.getOrder(5), orderService.getOrder(7) };
		assertThat(orders, hasItems(expectedOrders));
	}
	
	/**
	 * @verifies include orders for sub types if order type is specified
	 * @see OrderService#getActiveOrders(org.openmrs.Patient, org.openmrs.OrderType,
	 *      org.openmrs.CareSetting, java.util.Date)
	 */
	@Test
	public void getActiveOrders_shouldIncludeOrdersForSubTypesIfOrderTypeIsSpecified() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrders.xml");
		Patient patient = Context.getPatientService().getPatient(2);
		OrderType testOrderType = orderService.getOrderType(2);
		List<Order> orders = orderService.getActiveOrders(patient, testOrderType, null, null);
		assertEquals(5, orders.size());
		Order[] expectedOrder1 = { orderService.getOrder(7), orderService.getOrder(101), orderService.getOrder(102),
		        orderService.getOrder(103), orderService.getOrder(104) };
		assertThat(orders, hasItems(expectedOrder1));
		
		OrderType labTestOrderType = orderService.getOrderType(7);
		orders = orderService.getActiveOrders(patient, labTestOrderType, null, null);
		assertEquals(3, orders.size());
		Order[] expectedOrder2 = { orderService.getOrder(101), orderService.getOrder(103), orderService.getOrder(104) };
		assertThat(orders, hasItems(expectedOrder2));
	}
	
	/**
	 * @see {@link OrderService#discontinueOrder(org.openmrs.Order, String, java.util.Date, org.openmrs.Provider, org.openmrs.Encounter)}
	 */
	@Test
	@Verifies(value = "populate correct attributes on the discontinue and discontinued orders", method = "discontinueOrder(Order, String, Date, Provider, Encounter)")
	public void discontinueOrderWithNonCodedReason_shouldPopulateCorrectAttributesOnBothOrders() throws Exception {
		Order order = orderService.getOrderByOrderNumber("111");
		Encounter encounter = encounterService.getEncounter(3);
		Provider orderer = providerService.getProvider(1);
		assertTrue(OrderUtilTest.isActiveOrder(order, null));
		Date discontinueDate = new Date();
		String discontinueReasonNonCoded = "Test if I can discontinue this";
		
		Order discontinueOrder = orderService.discontinueOrder(order, discontinueReasonNonCoded, discontinueDate, orderer,
		    encounter);
		
		Assert.assertEquals(order.getDateStopped(), discontinueDate);
		Assert.assertNotNull(discontinueOrder);
		Assert.assertNotNull(discontinueOrder.getId());
		Assert.assertEquals(discontinueOrder.getAction(), Action.DISCONTINUE);
		Assert.assertEquals(discontinueOrder.getOrderReasonNonCoded(), discontinueReasonNonCoded);
		Assert.assertEquals(discontinueOrder.getPreviousOrder(), order);
	}
	
	/**
	 * @see {@link OrderService#discontinueOrder(org.openmrs.Order, org.openmrs.Concept, java.util.Date, org.openmrs.Provider, org.openmrs.Encounter)}
	 */
	@Test
	@Verifies(value = "populate correct attributes on the discontinue and discontinued orders", method = "discontinueOrder(Order, Concept, Date, Provider, Encounter)")
	public void discontinueOrderWithConcept_shouldPopulateCorrectAttributesOnBothOrders() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-discontinueReason.xml");
		
		Order order = orderService.getOrderByOrderNumber("111");
		Encounter encounter = encounterService.getEncounter(3);
		Provider orderer = providerService.getProvider(1);
		Date discontinueDate = new Date();
		Concept concept = Context.getConceptService().getConcept(1);
		
		Order discontinueOrder = orderService.discontinueOrder(order, concept, discontinueDate, orderer, encounter);
		
		Assert.assertEquals(order.getDateStopped(), discontinueDate);
		Assert.assertNotNull(discontinueOrder);
		Assert.assertNotNull(discontinueOrder.getId());
		Assert.assertEquals(discontinueOrder.getAction(), Action.DISCONTINUE);
		Assert.assertEquals(discontinueOrder.getOrderReason(), concept);
		Assert.assertEquals(discontinueOrder.getPreviousOrder(), order);
	}
	
	/**
	 * @see {@link OrderService#discontinueOrder(org.openmrs.Order, String, java.util.Date, org.openmrs.Provider, org.openmrs.Encounter)}
	 */
	@Test
	@Verifies(value = "fail for a discontinue order", method = "discontinueOrder(Order, String, Date, Provider, Encounter)")
	public void discontinueOrderWithNonCodedReason_shouldFailForADiscontinueOrder() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-discontinuedOrder.xml");
		OrderService orderService = Context.getOrderService();
		Order discontinueOrder = orderService.getOrder(26);
		Encounter encounter = encounterService.getEncounter(3);
		expectedException.expect(APIException.class);
		expectedException.expectMessage("An order with action " + Order.Action.DISCONTINUE + " cannot be discontinued.");
		orderService.discontinueOrder(discontinueOrder, "Test if I can discontinue this", null, null, encounter);
	}
	
	/**
	 * @see {@link OrderService#discontinueOrder(org.openmrs.Order, org.openmrs.Concept, java.util.Date, org.openmrs.Provider, org.openmrs.Encounter)}
	 */
	@Test
	@Verifies(value = "fail for a discontinue order", method = "discontinueOrder(Order, Concept, Date, Provider, Encounter)")
	public void discontinueOrderWithConcept_shouldFailForADiscontinueOrder() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-discontinuedOrder.xml");
		executeDataSet("org/openmrs/api/include/OrderServiceTest-discontinueReason.xml");
		OrderService orderService = Context.getOrderService();
		Order discontinueOrder = orderService.getOrder(26);
		assertEquals(Action.DISCONTINUE, discontinueOrder.getAction());
		Encounter encounter = encounterService.getEncounter(3);
		expectedException.expect(APIException.class);
		expectedException.expectMessage("An order with action " + Action.DISCONTINUE + " cannot be discontinued.");
		orderService.discontinueOrder(discontinueOrder, (Concept) null, null, null, encounter);
	}
	
	/**
	 * @see {@link OrderService#saveOrder(org.openmrs.Order, OrderContext)}
	 */
	@Test
	@Verifies(value = "discontinue existing active order if new order being saved with action to discontinue", method = "saveOrder(Order)")
	public void saveOrder_shouldDiscontinueExistingActiveOrderIfNewOrderBeingSavedWithActionToDiscontinue() throws Exception {
		DraftDrugOrder order = new DraftDrugOrder(orderService.getOrderType(1), providerService.getProvider(1), encounterService.getEncounter(5));
		order.setAction(Order.Action.DISCONTINUE);
		order.setOrderReasonNonCoded("Discontinue this");
		order.setEncounter(encounterService.getEncounter(5));
		order.setOrderer(providerService.getProvider(1));
		order.setConcept(conceptService.getConcept(88));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setEncounter(encounterService.getEncounter(3));
		order.setOrderType(orderService.getOrderType(1));
		order.setStartDate(new Date());
		order.setDosingType(DrugOrder.DosingType.SIMPLE);
		order.setDose(500.0);
		order.setDoseUnits(conceptService.getConcept(50));
		order.setFrequency(orderService.getOrderFrequency(1));
		order.setRoute(conceptService.getConcept(22));
		order.setNumRefills(10);
		order.setQuantity(20.0);
		order.setQuantityUnits(conceptService.getConcept(51));
		
		//We are trying to discontinue order id 111 in standardTestDataset.xml
		Order expectedPreviousOrder = orderService.getOrder(111);
		Assert.assertNull(expectedPreviousOrder.getDateStopped());
		
		order = (DrugOrder) orderService.saveOrder(order, null);
		
		Assert.assertNotNull("should populate dateStopped in previous order", expectedPreviousOrder.getDateStopped());
		Assert.assertNotNull("should save discontinue order", order.getId());
		Assert.assertEquals(expectedPreviousOrder, order.getPreviousOrder());
		Assert.assertNotNull(expectedPreviousOrder.getDateStopped());
	}
	
	/**
	 * @see {@link OrderService#saveOrder(org.openmrs.Order, OrderContext)}
	 */
	@Test
	@Verifies(value = "discontinue previousOrder if it is not already discontinued", method = "saveOrder(Order)")
	public void saveOrder_shouldDiscontinuePreviousOrderIfItIsNotAlreadyDiscontinued() throws Exception {
		//We are trying to discontinue order id 111 in standardTestDataset.xml
		DrugOrder order = new DrugOrder();
		order.setAction(Order.Action.DISCONTINUE);
		order.setOrderReasonNonCoded("Discontinue this");
		order.setEncounter(encounterService.getEncounter(5));
		order.setPatient(Context.getPatientService().getPatient(7));
		order.setOrderer(Context.getProviderService().getProvider(1));
		order.setConcept(Context.getConceptService().getConcept(88));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setEncounter(encounterService.getEncounter(3));
		order.setOrderType(orderService.getOrderType(1));
		order.setStartDate(new Date());
		order.setDosingType(DrugOrder.DosingType.SIMPLE);
		order.setDose(500.0);
		order.setDoseUnits(conceptService.getConcept(50));
		order.setFrequency(orderService.getOrderFrequency(1));
		order.setRoute(conceptService.getConcept(22));
		order.setNumRefills(10);
		order.setQuantity(20.0);
		order.setQuantityUnits(conceptService.getConcept(51));
		Order previousOrder = orderService.getOrder(111);
		assertTrue(OrderUtilTest.isActiveOrder(previousOrder, null));
		order.setPreviousOrder(previousOrder);
		
		orderService.saveOrder(order, null);
		
		Assert.assertNotNull("previous order should be discontinued", previousOrder.getDateStopped());
	}
	
	/**
	 * @see {@link OrderService#saveOrder(org.openmrs.Order, OrderContext)}
	 */
	@Test
	@Verifies(value = "fail if concept in previous order does not match this concept", method = "saveOrder(Order)")
	public void saveOrder_shouldFailIfConceptInPreviousOrderDoesNotMatchThisConcept() throws Exception {
		Order previousOrder = orderService.getOrder(7);
		assertTrue(OrderUtilTest.isActiveOrder(previousOrder, null));
		Order order = previousOrder.cloneForDiscontinuing();
		order.setStartDate(new Date());
		order.setOrderReasonNonCoded("Discontinue this");
		order.setEncounter(encounterService.getEncounter(6));
		order.setOrderer(providerService.getProvider(1));
		Concept newConcept = conceptService.getConcept(5089);
		assertFalse(previousOrder.getConcept().equals(newConcept));
		order.setConcept(newConcept);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The concept of the previous order and the new one order don't match");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies reject a future discontinueDate
	 * @see OrderService#discontinueOrder(org.openmrs.Order, org.openmrs.Concept, java.util.Date,
	 *      org.openmrs.Provider, org.openmrs.Encounter)
	 */
	@Test(expected = IllegalArgumentException.class)
	public void discontinueOrder_shouldRejectAFutureDiscontinueDate() throws Exception {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.HOUR_OF_DAY, 1);
		Patient patient = Context.getPatientService().getPatient(2);
		CareSetting careSetting = orderService.getCareSetting(1);
		Order orderToDiscontinue = orderService.getActiveOrders(patient, null, careSetting, null).get(0);
		Encounter encounter = encounterService.getEncounter(3);
		orderService.discontinueOrder(orderToDiscontinue, new Concept(), cal.getTime(), null, encounter);
	}
	
	/**
	 * @verifies fail if discontinueDate is in the future
	 * @see OrderService#discontinueOrder(org.openmrs.Order, String, java.util.Date,
	 *      org.openmrs.Provider, org.openmrs.Encounter)
	 */
	@Test(expected = IllegalArgumentException.class)
	public void discontinueOrder_shouldFailIfDiscontinueDateIsInTheFuture() throws Exception {
		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.HOUR_OF_DAY, 1);
		Order orderToDiscontinue = orderService.getActiveOrders(Context.getPatientService().getPatient(2), null,
		    orderService.getCareSetting(1), null).get(0);
		Encounter encounter = encounterService.getEncounter(3);
		orderService.discontinueOrder(orderToDiscontinue, "Testing", cal.getTime(), null, encounter);
	}
	
	/**
	 * @verifies pass if the existing drug order matches the concept and drug of the DC order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldPassIfTheExistingDrugOrderMatchesTheConceptAndDrugOfTheDCOrder() throws Exception {
		final DrugOrder orderToDiscontinue = (DrugOrder) orderService.getOrder(444);
		assertTrue(OrderUtilTest.isActiveOrder(orderToDiscontinue, null));
		
		DrugOrder order = new DrugOrder();
		order.setDrug(orderToDiscontinue.getDrug());
		order.setOrderType(orderService.getOrderTypeByName("Drug order"));
		order.setAction(Order.Action.DISCONTINUE);
		order.setOrderReasonNonCoded("Discontinue this");
		order.setPatient(orderToDiscontinue.getPatient());
		order.setConcept(orderToDiscontinue.getConcept());
		order.setOrderer(orderToDiscontinue.getOrderer());
		order.setCareSetting(orderToDiscontinue.getCareSetting());
		order.setEncounter(encounterService.getEncounter(6));
		order.setStartDate(new Date());
		order.setDosingType(DrugOrder.DosingType.SIMPLE);
		order.setDose(orderToDiscontinue.getDose());
		order.setDoseUnits(orderToDiscontinue.getDoseUnits());
		order.setRoute(orderToDiscontinue.getRoute());
		order.setFrequency(orderToDiscontinue.getFrequency());
		order.setQuantity(orderToDiscontinue.getQuantity());
		order.setQuantityUnits(orderToDiscontinue.getQuantityUnits());
		order.setNumRefills(orderToDiscontinue.getNumRefills());
		
		orderService.saveOrder(order, null);
		
		Assert.assertNotNull("previous order should be discontinued", orderToDiscontinue.getDateStopped());
	}
	
	/**
	 * @verifies fail if the existing drug order matches the concept and not drug of the DC order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfTheExistingDrugOrderMatchesTheConceptAndNotDrugOfTheDCOrder() throws Exception {
		final DrugOrder orderToDiscontinue = (DrugOrder) orderService.getOrder(5);
		assertTrue(OrderUtilTest.isActiveOrder(orderToDiscontinue, null));
		
		//create a different test drug
		Drug discontinuationOrderDrug = new Drug();
		discontinuationOrderDrug.setConcept(orderToDiscontinue.getConcept());
		discontinuationOrderDrug = conceptService.saveDrug(discontinuationOrderDrug);
		assertNotEquals(discontinuationOrderDrug, orderToDiscontinue.getDrug());
		assertNotNull(orderToDiscontinue.getDrug());
		
		DrugOrder order = orderToDiscontinue.cloneForRevision();
		order.setStartDate(new Date());
		order.setOrderer(providerService.getProvider(1));
		order.setEncounter(encounterService.getEncounter(6));
		order.setDrug(discontinuationOrderDrug);
		order.setOrderReasonNonCoded("Discontinue this");
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The drug of the previous order and the new one order don't match");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies fail for a stopped order
	 * @see OrderService#discontinueOrder(org.openmrs.Order, org.openmrs.Concept, java.util.Date,
	 *      org.openmrs.Provider, org.openmrs.Encounter)
	 */
	@Test(expected = APIException.class)
	public void discontinueOrder_shouldFailForAStoppedOrder() throws Exception {
		Order orderToDiscontinue = orderService.getOrder(1);
		Encounter encounter = encounterService.getEncounter(3);
		assertNotNull(orderToDiscontinue.getDateStopped());
		orderService.discontinueOrder(orderToDiscontinue, Context.getConceptService().getConcept(1), null, null, encounter);
	}
	
	/**
	 * @verifies fail for a voided order
	 * @see OrderService#discontinueOrder(org.openmrs.Order, String, java.util.Date,
	 *      org.openmrs.Provider, org.openmrs.Encounter)
	 */
	@Test(expected = APIException.class)
	public void discontinueOrder_shouldFailForAVoidedOrder() throws Exception {
		Order orderToDiscontinue = orderService.getOrder(8);
		Encounter encounter = encounterService.getEncounter(3);
		assertTrue(orderToDiscontinue.isVoided());
		orderService.discontinueOrder(orderToDiscontinue, "testing", null, null, encounter);
	}
	
	/**
	 * @verifies fail for an expired order
	 * @see OrderService#discontinueOrder(org.openmrs.Order, org.openmrs.Concept, java.util.Date,
	 *      org.openmrs.Provider, org.openmrs.Encounter)
	 */
	@Test(expected = APIException.class)
	public void discontinueOrder_shouldFailForAnExpiredOrder() throws Exception {
		Order orderToDiscontinue = orderService.getOrder(6);
		Encounter encounter = encounterService.getEncounter(3);
		assertNotNull(orderToDiscontinue.getAutoExpireDate());
		assertTrue(orderToDiscontinue.getAutoExpireDate().before(new Date()));
		orderService.discontinueOrder(orderToDiscontinue, Context.getConceptService().getConcept(1), null, null, encounter);
	}
	
	/**
	 * @verifies not allow editing an existing order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowEditingAnExistingOrder() throws Exception {
		final DrugOrder order = (DrugOrder) orderService.getOrder(5);
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot edit an existing order, you need to revise it instead");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies return the care setting with the specified uuid
	 * @see OrderService#getCareSettingByUuid(String)
	 */
	@Test
	public void getCareSettingByUuid_shouldReturnTheCareSettingWithTheSpecifiedUuid() throws Exception {
		CareSetting cs = orderService.getCareSettingByUuid("6f0c9a92-6f24-11e3-af88-005056821db0");
		assertEquals(1, cs.getId().intValue());
	}
	
	/**
	 * @verifies return the care setting with the specified name
	 * @see OrderService#getCareSettingByName(String)
	 */
	@Test
	public void getCareSettingByName_shouldReturnTheCareSettingWithTheSpecifiedName() throws Exception {
		CareSetting cs = orderService.getCareSettingByName("INPATIENT");
		assertEquals(2, cs.getId().intValue());
		
		//should also be case insensitive
		cs = orderService.getCareSettingByName("inpatient");
		assertEquals(2, cs.getId().intValue());
	}
	
	/**
	 * @verifies return only un retired care settings if includeRetired is set to false
	 * @see OrderService#getCareSettings(boolean)
	 */
	@Test
	public void getCareSettings_shouldReturnOnlyUnRetiredCareSettingsIfIncludeRetiredIsSetToFalse() throws Exception {
		List<CareSetting> careSettings = orderService.getCareSettings(false);
		assertEquals(2, careSettings.size());
		assertTrue(containsId(careSettings, 1));
		assertTrue(containsId(careSettings, 2));
	}
	
	/**
	 * @verifies return retired care settings if includeRetired is set to true
	 * @see OrderService#getCareSettings(boolean)
	 */
	@Test
	public void getCareSettings_shouldReturnRetiredCareSettingsIfIncludeRetiredIsSetToTrue() throws Exception {
		CareSetting retiredCareSetting = orderService.getCareSetting(3);
		assertTrue(retiredCareSetting.isRetired());
		List<CareSetting> careSettings = orderService.getCareSettings(true);
		assertEquals(3, careSettings.size());
		assertTrue(containsId(careSettings, retiredCareSetting.getCareSettingId()));
	}
	
	/**
	 * @verifies not allow revising a stopped order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowRevisingAStoppedOrder() throws Exception {
		Order originalOrder = orderService.getOrder(1);
		assertNotNull(originalOrder.getDateStopped());
		Order revisedOrder = originalOrder.cloneForRevision();
		revisedOrder.setEncounter(encounterService.getEncounter(4));
		revisedOrder.setInstructions("Take after a meal");
		revisedOrder.setOrderer(providerService.getProvider(1));
		revisedOrder.setStartDate(new Date());
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot discontinue an order that is already stopped, expired or voided");
		orderService.saveOrder(revisedOrder, null);
	}
	
	/**
	 * @verifies not allow revising a voided order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowRevisingAVoidedOrder() throws Exception {
		Order originalOrder = orderService.getOrder(8);
		assertTrue(originalOrder.isVoided());
		Order revisedOrder = originalOrder.cloneForRevision();
		revisedOrder.setEncounter(encounterService.getEncounter(6));
		revisedOrder.setInstructions("Take after a meal");
		revisedOrder.setOrderer(providerService.getProvider(1));
		revisedOrder.setStartDate(new Date());
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot discontinue an order that is already stopped, expired or voided");
		orderService.saveOrder(revisedOrder, null);
	}
	
	/**
	 * @verifies not allow revising an expired order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowRevisingAnExpiredOrder() throws Exception {
		Order originalOrder = orderService.getOrder(6);
		assertNotNull(originalOrder.getAutoExpireDate());
		assertTrue(originalOrder.getAutoExpireDate().before(new Date()));
		Order revisedOrder = originalOrder.cloneForRevision();
		revisedOrder.setEncounter(encounterService.getEncounter(6));
		revisedOrder.setInstructions("Take after a meal");
		revisedOrder.setOrderer(providerService.getProvider(1));
		revisedOrder.setStartDate(new Date());
		revisedOrder.setAutoExpireDate(new Date());
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot discontinue an order that is already stopped, expired or voided");
		orderService.saveOrder(revisedOrder, null);
	}
	
	/**
	 * @verifies not allow revising an order with no previous order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowRevisingAnOrderWithNoPreviousOrder() throws Exception {
		Order originalOrder = orderService.getOrder(111);
		assertTrue(originalOrder.isCurrent());
		Order revisedOrder = originalOrder.cloneForRevision();
		revisedOrder.setEncounter(encounterService.getEncounter(5));
		revisedOrder.setInstructions("Take after a meal");
		revisedOrder.setPreviousOrder(null);
		revisedOrder.setOrderer(providerService.getProvider(1));
		revisedOrder.setStartDate(new Date());
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Previous Order is required for a revised order");
		orderService.saveOrder(revisedOrder, null);
	}
	
	/**
	 * @verifies save a revised order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldSaveARevisedOrder() throws Exception {
		Order originalOrder = orderService.getOrder(111);
		assertTrue(originalOrder.isCurrent());
		final Patient patient = originalOrder.getPatient();
		List<Order> originalActiveOrders = orderService.getActiveOrders(patient, null, null, null);
		final int originalOrderCount = originalActiveOrders.size();
		assertTrue(originalActiveOrders.contains(originalOrder));
		Order revisedOrder = originalOrder.cloneForRevision();
		revisedOrder.setEncounter(encounterService.getEncounter(5));
		revisedOrder.setInstructions("Take after a meal");
		revisedOrder.setStartDate(new Date());
		revisedOrder.setOrderer(providerService.getProvider(1));
		revisedOrder.setEncounter(encounterService.getEncounter(3));
		orderService.saveOrder(revisedOrder, null);
		
		//If the time is too close, the original order may be returned because it
		//dateStopped will be exactly the same as the asOfDate(now) to the millisecond
		Thread.sleep(1);
		List<Order> activeOrders = orderService.getActiveOrders(patient, null, null, null);
		assertEquals(originalOrderCount, activeOrders.size());
		assertFalse(originalOrder.isCurrent());
	}
	
	/**
	 * @verifies get non retired frequencies with names matching the phrase if includeRetired is
	 *           false
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldGetNonRetiredFrequenciesWithNamesMatchingThePhraseIfIncludeRetiredIsFalse()
	        throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml");
		List<OrderFrequency> orderFrequencies = orderService.getOrderFrequencies("once", Locale.US, false, false);
		assertEquals(2, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 100));
		assertTrue(containsId(orderFrequencies, 102));
		
		//should match anywhere in the concept name
		orderFrequencies = orderService.getOrderFrequencies("nce", Locale.US, false, false);
		assertEquals(2, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 100));
		assertTrue(containsId(orderFrequencies, 102));
	}
	
	/**
	 * @verifies include retired frequencies if includeRetired is set to true
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldIncludeRetiredFrequenciesIfIncludeRetiredIsSetToTrue() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml");
		List<OrderFrequency> orderFrequencies = orderService.getOrderFrequencies("ce", Locale.US, false, true);
		assertEquals(4, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 100));
		assertTrue(containsId(orderFrequencies, 101));
		assertTrue(containsId(orderFrequencies, 102));
		assertTrue(containsId(orderFrequencies, 103));
	}
	
	/**
	 * @verifies get frequencies with names that match the phrase and locales if exact locale is
	 *           false
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldGetFrequenciesWithNamesThatMatchThePhraseAndLocalesIfExactLocaleIsFalse()
	        throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml");
		List<OrderFrequency> orderFrequencies = orderService.getOrderFrequencies("ce", Locale.US, false, false);
		assertEquals(3, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 100));
		assertTrue(containsId(orderFrequencies, 101));
		assertTrue(containsId(orderFrequencies, 102));
	}
	
	/**
	 * @verifies get frequencies with names that match the phrase and locale if exact locale is true
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldGetFrequenciesWithNamesThatMatchThePhraseAndLocaleIfExactLocaleIsTrue()
	        throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml");
		List<OrderFrequency> orderFrequencies = orderService.getOrderFrequencies("ce", Locale.US, true, false);
		assertEquals(1, orderFrequencies.size());
		assertEquals(102, orderFrequencies.get(0).getOrderFrequencyId().intValue());
		
		orderFrequencies = orderService.getOrderFrequencies("ce", Locale.ENGLISH, true, false);
		assertEquals(2, orderFrequencies.size());
		assertTrue(containsId(orderFrequencies, 100));
		assertTrue(containsId(orderFrequencies, 101));
	}
	
	/**
	 * @verifies return unique frequencies
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldReturnUniqueFrequencies() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrderFrequencies.xml");
		final String searchPhrase = "once";
		final Locale locale = Locale.ENGLISH;
		List<OrderFrequency> orderFrequencies = orderService.getOrderFrequencies(searchPhrase, locale, true, false);
		assertEquals(1, orderFrequencies.size());
		final OrderFrequency expectedOrderFrequency = orderService.getOrderFrequency(100);
		assertEquals(expectedOrderFrequency, orderFrequencies.get(0));
		
		//Add a new name to the frequency concept so that our search phrase matches on 2
		//concept names for the same frequency concept
		Concept frequencyConcept = expectedOrderFrequency.getConcept();
		final String newConceptName = searchPhrase + " A Day";
		frequencyConcept.addName(new ConceptName(newConceptName, locale));
		conceptService.saveConcept(frequencyConcept);
		
		orderFrequencies = orderService.getOrderFrequencies(searchPhrase, locale, true, false);
		assertEquals(1, orderFrequencies.size());
		assertEquals(expectedOrderFrequency, orderFrequencies.get(0));
	}
	
	/**
	 * @verifies reject a null search phrase
	 * @see OrderService#getOrderFrequencies(String, java.util.Locale, boolean, boolean)
	 */
	@Test
	public void getOrderFrequencies_shouldRejectANullSearchPhrase() throws Exception {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("searchPhrase is required");
		orderService.getOrderFrequencies(null, Locale.ENGLISH, false, false);
	}
	
	@Test
	@Verifies(value = "should retire given order frequency", method = "retireOrderFrequency(orderFrequency, String)")
	public void retireOrderFrequency_shouldRetireGivenOrderFrequency() throws Exception {
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(1);
		assertNotNull(orderFrequency);
		Assert.assertFalse(orderFrequency.isRetired());
		Assert.assertNull(orderFrequency.getRetireReason());
		Assert.assertNull(orderFrequency.getDateRetired());
		
		Context.getOrderService().retireOrderFrequency(orderFrequency, "retire reason");
		
		orderFrequency = Context.getOrderService().getOrderFrequency(1);
		assertNotNull(orderFrequency);
		assertTrue(orderFrequency.isRetired());
		assertEquals("retire reason", orderFrequency.getRetireReason());
		assertNotNull(orderFrequency.getDateRetired());
		
		//Should not change the number of order frequencies.
		assertEquals(3, Context.getOrderService().getOrderFrequencies(true).size());
	}
	
	@Test
	@Verifies(value = "should unretire given order frequency", method = "unretireOrderFrequency(OrderFrequency)")
	public void unretireOrderFrequency_shouldUnretireGivenOrderFrequency() throws Exception {
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(3);
		assertNotNull(orderFrequency);
		assertTrue(orderFrequency.isRetired());
		assertEquals("Some Retire Reason", orderFrequency.getRetireReason());
		assertNotNull(orderFrequency.getDateRetired());
		
		Context.getOrderService().unretireOrderFrequency(orderFrequency);
		
		orderFrequency = Context.getOrderService().getOrderFrequency(3);
		assertNotNull(orderFrequency);
		assertFalse(orderFrequency.isRetired());
		assertNull(orderFrequency.getRetireReason());
		assertNull(orderFrequency.getDateRetired());
		
		//Should not change the number of order frequencies.
		assertEquals(3, Context.getOrderService().getOrderFrequencies(true).size());
	}
	
	@Test
	@Verifies(value = "should delete given order frequency", method = "purgeOrderFrequency(OrderFrequency)")
	public void purgeOrderFrequency_shouldDeleteGivenOrderFrequency() throws Exception {
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(3);
		assertNotNull(orderFrequency);
		
		Context.getOrderService().purgeOrderFrequency(orderFrequency);
		
		orderFrequency = Context.getOrderService().getOrderFrequency(3);
		Assert.assertNull(orderFrequency);
		
		//Should reduce the existing number of order frequencies.
		assertEquals(2, Context.getOrderService().getOrderFrequencies(true).size());
	}
	
	/**
	 * @see {@link OrderService#saveOrderFrequency(OrderFrequency)}
	 */
	@Test
	@Verifies(value = "should add a new order frequency to the database", method = "saveOrderFrequency(OrderFrequency)")
	public void saveOrderFrequency_shouldAddANewOrderFrequencyToTheDatabase() throws Exception {
		Concept concept = new Concept();
		concept.addName(new ConceptName("new name", Context.getLocale()));
		concept.setConceptClass(conceptService.getConceptClassByName("Frequency"));
		concept = conceptService.saveConcept(concept);
		OrderService os = Context.getOrderService();
		Integer originalSize = os.getOrderFrequencies(true).size();
		OrderFrequency orderFrequency = new OrderFrequency();
		orderFrequency.setConcept(concept);
		orderFrequency.setFrequencyPerDay(2d);
		
		orderFrequency = os.saveOrderFrequency(orderFrequency);
		
		assertNotNull(orderFrequency.getId());
		assertNotNull(orderFrequency.getUuid());
		assertNotNull(orderFrequency.getCreator());
		assertNotNull(orderFrequency.getDateCreated());
		assertEquals(originalSize + 1, os.getOrderFrequencies(true).size());
	}
	
	/**
	 * @see {@link OrderService#saveOrderFrequency(OrderFrequency)}
	 */
	@Test
	@Verifies(value = "should edit an existing order frequency that is not in use", method = "saveOrderFrequency(OrderFrequency)")
	public void saveOrderFrequency_shouldEditAnExistingOrderFrequencyThatIsNotInUse() throws Exception {
		executeDataSet(OTHER_ORDER_FREQUENCIES_XML);
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(100);
		assertNotNull(orderFrequency);
		
		orderFrequency.setFrequencyPerDay(4d);
		Context.getOrderService().saveOrderFrequency(orderFrequency);
	}
	
	/**
	 * @see {@link OrderService#saveOrderFrequency(OrderFrequency)}
	 */
	@Test
	@Verifies(value = "should not allow editing an existing order frequency that is in use", method = "saveOrderFrequency(OrderFrequency)")
	public void saveOrderFrequency_shouldNotAllowEditingAnExistingOrderFrequencyThatIsInUse() throws Exception {
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(1);
		assertNotNull(orderFrequency);
		
		orderFrequency.setFrequencyPerDay(4d);
		expectedException.expect(APIException.class);
		expectedException.expectMessage("This order frequency cannot be edited because it is already in use");
		Context.getOrderService().saveOrderFrequency(orderFrequency);
	}
	
	/**
	 * @see {@link OrderService#purgeOrderFrequency(OrderFrequency)}
	 */
	@Test
	@Verifies(value = "should not allow deleting an order frequency that is in use", method = "purgeOrderFrequency(OrderFrequency)")
	public void purgeOrderFrequency_shouldNotAllowDeletingAnOrderFrequencyThatIsInUse() throws Exception {
		OrderFrequency orderFrequency = Context.getOrderService().getOrderFrequency(1);
		assertNotNull(orderFrequency);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("This order frequency cannot be deleted because it is already in use");
		Context.getOrderService().purgeOrderFrequency(orderFrequency);
	}
	
	@Test
	public void saveOrderWithScheduledDate_shouldAddANewOrderWithScheduledDateToTheDatabase() {
		Date scheduledDate = new Date();
		Order order = new Order();
		order.setAction(Action.NEW);
		order.setPatient(Context.getPatientService().getPatient(7));
		order.setConcept(Context.getConceptService().getConcept(88));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setOrderer(orderService.getOrder(1).getOrderer());
		order.setEncounter(encounterService.getEncounter(3));
		order.setStartDate(new Date());
		order.setScheduledDate(scheduledDate);
		order.setUrgency(Order.Urgency.ON_SCHEDULED_DATE);
		order.setEncounter(encounterService.getEncounter(3));
		order.setOrderType(orderService.getOrderType(17));
		order = orderService.saveOrder(order, null);
		Order newOrder = orderService.getOrder(order.getOrderId());
		assertNotNull(order);
		assertEquals(scheduledDate, order.getScheduledDate());
		assertNotNull(newOrder);
		assertEquals(scheduledDate, newOrder.getScheduledDate());
		
	}
	
	/**
	 * @verifies set order number specified in the context if specified
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldSetOrderNumberSpecifiedInTheContextIfSpecified() throws Exception {
		GlobalProperty gp = new GlobalProperty(OpenmrsConstants.GP_ORDER_NUMBER_GENERATOR_BEAN_ID,
		        "orderEntry.OrderNumberGenerator");
		Context.getAdministrationService().saveGlobalProperty(gp);
		Order order = new TestOrder();
		order.setEncounter(encounterService.getEncounter(6));
		order.setPatient(patientService.getPatient(2));
		order.setConcept(conceptService.getConcept(5497));
		order.setOrderer(providerService.getProvider(1));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setOrderType(orderService.getOrderType(2));
		order.setEncounter(encounterService.getEncounter(6));
		order.setStartDate(new Date());
		OrderContext orderCtxt = new OrderContext();
		final String expectedOrderNumber = "Testing";
		orderCtxt.setAttribute(TimestampOrderNumberGenerator.NEXT_ORDER_NUMBER, expectedOrderNumber);
		order = orderService.saveOrder(order, orderCtxt);
		assertEquals(expectedOrderNumber, order.getOrderNumber());
	}
	
	/**
	 * @verifies set the order number returned by the configured generator
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldSetTheOrderNumberReturnedByTheConfiguredGenerator() throws Exception {
		GlobalProperty gp = new GlobalProperty(OpenmrsConstants.GP_ORDER_NUMBER_GENERATOR_BEAN_ID,
		        "orderEntry.OrderNumberGenerator");
		Context.getAdministrationService().saveGlobalProperty(gp);
		Order order = new TestOrder();
		order.setPatient(patientService.getPatient(2));
		order.setConcept(conceptService.getConcept(5497));
		order.setOrderer(providerService.getProvider(1));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setOrderType(orderService.getOrderType(2));
		order.setEncounter(encounterService.getEncounter(6));
		order.setStartDate(new Date());
		order = orderService.saveOrder(order, null);
		assertTrue(order.getOrderNumber().startsWith(TimestampOrderNumberGenerator.ORDER_NUMBER_PREFIX));
	}
	
	/**
	 * @verifies find order type object given valid id
	 * @see OrderService#getOrderType(Integer)
	 */
	@Test
	public void getOrderType_shouldFindOrderTypeObjectGivenValidId() throws Exception {
		OrderType orderType = Context.getOrderService().getOrderType(1);
		assertEquals("Drug order", orderType.getName());
	}
	
	/**
	 * @verifies return null if no order type object found with given id
	 * @see OrderService#getOrderType(Integer)
	 */
	@Test
	public void getOrderType_shouldReturnNullIfNoOrderTypeObjectFoundWithGivenId() throws Exception {
		OrderType orderType = Context.getOrderService().getOrderType(1000);
		assertNull(orderType);
	}
	
	/**
	 * @verifies find order type object given valid uuid
	 * @see OrderService#getOrderTypeByUuid(String)
	 */
	@Test
	public void getOrderTypeByUuid_shouldFindOrderTypeObjectGivenValidUuid() throws Exception {
		OrderType orderType = Context.getOrderService().getOrderTypeByUuid("2ca568f3-a64a-11e3-9aeb-50e549534c5e");
		assertEquals("Drug order", orderType.getName());
	}
	
	/**
	 * @verifies return null if no order type object found with given uuid
	 * @see OrderService#getOrderTypeByUuid(String)
	 */
	@Test
	public void getOrderTypeByUuid_shouldReturnNullIfNoOrderTypeObjectFoundWithGivenUuid() throws Exception {
		OrderType orderType = Context.getOrderService().getOrderTypeByUuid("some random uuid");
		assertNull(orderType);
	}
	
	/**
	 * @verifies get all order types if includeRetired is set to true
	 * @see OrderService#getOrderTypes(boolean)
	 */
	@Test
	public void getOrderTypes_shouldGetAllOrderTypesIfIncludeRetiredIsSetToTrue() throws Exception {
		assertEquals(14, orderService.getOrderTypes(true).size());
	}
	
	/**
	 * @verifies get all non retired order types if includeRetired is set to false
	 * @see OrderService#getOrderTypes(boolean)
	 */
	@Test
	public void getOrderTypes_shouldGetAllNonRetiredOrderTypesIfIncludeRetiredIsSetToFalse() throws Exception {
		assertEquals(11, orderService.getOrderTypes(false).size());
	}
	
	/**
	 * @verifies return the order type that matches the specified name
	 * @see OrderService#getOrderTypeByName(String)
	 */
	@Test
	public void getOrderTypeByName_shouldReturnTheOrderTypeThatMatchesTheSpecifiedName() throws Exception {
		OrderType orderType = Context.getOrderService().getOrderTypeByName("Drug order");
		assertEquals("2ca568f3-a64a-11e3-9aeb-50e549534c5e", orderType.getUuid());
	}
	
	/**
	 * @verifies fail if patient is null
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldFailIfPatientIsNull() throws Exception {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Patient is required");
		orderService.getOrders(null, null, null, false);
	}
	
	/**
	 * @verifies fail if careSetting is null
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldFailIfCareSettingIsNull() throws Exception {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("CareSetting is required");
		orderService.getOrders(new Patient(), null, null, false);
	}
	
	/**
	 * @verifies get the orders that match all the arguments
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldGetTheOrdersThatMatchAllTheArguments() throws Exception {
		Patient patient = patientService.getPatient(2);
		CareSetting outPatient = orderService.getCareSetting(1);
		OrderType testOrderType = orderService.getOrderType(2);
		List<Order> testOrders = orderService.getOrders(patient, outPatient, testOrderType, false);
		assertEquals(3, testOrders.size());
		TestUtil.containsId(testOrders, 6);
		TestUtil.containsId(testOrders, 7);
		TestUtil.containsId(testOrders, 9);
		
		OrderType drugOrderType = orderService.getOrderType(1);
		List<Order> drugOrders = orderService.getOrders(patient, outPatient, drugOrderType, false);
		assertEquals(5, drugOrders.size());
		TestUtil.containsId(drugOrders, 2);
		TestUtil.containsId(drugOrders, 3);
		TestUtil.containsId(drugOrders, 44);
		TestUtil.containsId(drugOrders, 444);
		TestUtil.containsId(drugOrders, 5);
		
		CareSetting inPatient = orderService.getCareSetting(2);
		List<Order> inPatientDrugOrders = orderService.getOrders(patient, inPatient, drugOrderType, false);
		assertEquals(222, inPatientDrugOrders.get(0).getOrderId().intValue());
	}
	
	/**
	 * @verifies get all unvoided matches if includeVoided is set to false
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldGetAllUnvoidedMatchesIfIncludeVoidedIsSetToFalse() throws Exception {
		Patient patient = patientService.getPatient(2);
		CareSetting outPatient = orderService.getCareSetting(1);
		OrderType testOrderType = orderService.getOrderType(2);
		assertEquals(3, orderService.getOrders(patient, outPatient, testOrderType, false).size());
	}
	
	/**
	 * @verifies include voided matches if includeVoided is set to true
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldIncludeVoidedMatchesIfIncludeVoidedIsSetToTrue() throws Exception {
		Patient patient = patientService.getPatient(2);
		CareSetting outPatient = orderService.getCareSetting(1);
		OrderType testOrderType = orderService.getOrderType(2);
		assertEquals(4, orderService.getOrders(patient, outPatient, testOrderType, true).size());
	}
	
	/**
	 * @verifies include orders for sub types if order type is specified
	 * @see OrderService#getOrders(org.openmrs.Patient, org.openmrs.CareSetting,
	 *      org.openmrs.OrderType, boolean)
	 */
	@Test
	public void getOrders_shouldIncludeOrdersForSubTypesIfOrderTypeIsSpecified() throws Exception {
		executeDataSet("org/openmrs/api/include/OrderServiceTest-otherOrders.xml");
		Patient patient = patientService.getPatient(2);
		OrderType testOrderType = orderService.getOrderType(2);
		CareSetting outPatient = orderService.getCareSetting(1);
		List<Order> orders = orderService.getOrders(patient, outPatient, testOrderType, false);
		assertEquals(7, orders.size());
		Order[] expectedOrder1 = { orderService.getOrder(6), orderService.getOrder(7), orderService.getOrder(9),
		        orderService.getOrder(101), orderService.getOrder(102), orderService.getOrder(103),
		        orderService.getOrder(104) };
		assertThat(orders, hasItems(expectedOrder1));
		
		OrderType labTestOrderType = orderService.getOrderType(7);
		orders = orderService.getOrders(patient, outPatient, labTestOrderType, false);
		assertEquals(3, orderService.getOrders(patient, outPatient, labTestOrderType, false).size());
		Order[] expectedOrder2 = { orderService.getOrder(101), orderService.getOrder(103), orderService.getOrder(104) };
		assertThat(orders, hasItems(expectedOrder2));
	}
	
	/**
	 * @verifies fail if patient is null
	 * @see OrderService#getAllOrdersByPatient(org.openmrs.Patient)
	 */
	@Test
	public void getAllOrdersByPatient_shouldFailIfPatientIsNull() throws Exception {
		expectedException.expect(IllegalArgumentException.class);
		expectedException.expectMessage("Patient is required");
		orderService.getAllOrdersByPatient(null);
	}
	
	/**
	 * @verifies get all the orders for the specified patient
	 * @see OrderService#getAllOrdersByPatient(org.openmrs.Patient)
	 */
	@Test
	public void getAllOrdersByPatient_shouldGetAllTheOrdersForTheSpecifiedPatient() throws Exception {
		assertEquals(12, orderService.getAllOrdersByPatient(patientService.getPatient(2)).size());
		assertEquals(2, orderService.getAllOrdersByPatient(patientService.getPatient(7)).size());
	}
	
	/**
	 * @verifies set order type if null but mapped to the concept class
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldSetOrderTypeIfNullButMappedToTheConceptClass() throws Exception {
		Order order = new Order();
		order.setPatient(patientService.getPatient(2));
		order.setConcept(conceptService.getConcept(5497));
		order.setOrderer(providerService.getProvider(1));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setEncounter(encounterService.getEncounter(6));
		order.setStartDate(new Date());
		order = orderService.saveOrder(order, null);
		assertEquals(2, order.getOrderType().getOrderTypeId().intValue());
	}
	
	/**
	 * @verifies fail if order type is null and not mapped to the concept class
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfOrderTypeIsNullAndNotMappedToTheConceptClass() throws Exception {
		Order order = new Order();
		order.setPatient(patientService.getPatient(2));
		order.setConcept(conceptService.getConcept(3));
		order.setOrderer(providerService.getProvider(1));
		order.setCareSetting(orderService.getCareSetting(1));
		order.setEncounter(encounterService.getEncounter(6));
		order.setStartDate(new Date());
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot determine the order type of the order");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @see {@link OrderService#saveOrderType(org.openmrs.OrderType)}
	 */
	@Test
	@Verifies(value = "should save order type", method = "saveOrderType(org.openmrs.OrderType)")
	public void saveOrderType_shouldAddNewOrderTypeToTheDatabase() {
		OrderService orderService = Context.getOrderService();
		int orderTypeCount = orderService.getOrderTypes(true).size();
		OrderType orderType = new OrderType();
		orderType.setName("New Order");
		orderType.setJavaClassName("org.openmrs.NewTestOrder");
		orderType.setDescription("New order type for testing");
		orderType.setRetired(false);
		orderType = orderService.saveOrderType(orderType);
		assertNotNull(orderType);
		assertEquals("New Order", orderType.getName());
		assertNotNull(orderType.getId());
		assertEquals((orderTypeCount + 1), orderService.getOrderTypes(true).size());
	}
	
	/**
	 * @see {@link OrderService#purgeOrderType(org.openmrs.OrderType)}
	 */
	@Test
	@Verifies(value = "should purge order type", method = "purgeOrderType(org.openmrs.OrderType)")
	public void purgeOrderType_shouldPurgeOrderTypeIfNotUse() {
		OrderService orderService = Context.getOrderService();
		OrderType orderType = orderService.getOrderType(13);
		assertNotNull(orderType);
		orderService.purgeOrderType(orderType);
		assertNull(orderService.getOrderType(13));
	}
	
	/**
	 * @see {@link OrderService#purgeOrderType(org.openmrs.OrderType)}
	 */
	@Test
	@Verifies(value = "should purge order type", method = "purgeOrderType(org.openmrs.OrderType)")
	public void purgeOrderType_shouldNotPurgeOrderTypeIfUse() {
		OrderService orderService = Context.getOrderService();
		OrderType orderType = orderService.getOrderType(1);
		assertNotNull(orderType);
		expectedException.expect(APIException.class);
		expectedException.expectMessage("This order type cannot be deleted because it is already in use");
		orderService.purgeOrderType(orderType);
	}
	
	/**
	 * @see {@link OrderService#retireOrderType(org.openmrs.OrderType, String)}
	 */
	@Test
	@Verifies(value = "should retire order type", method = "retireOrderType(org.openmrs.OrderType, String)")
	public void retireOrderType_shouldRetiredTheGivenUnretiredOrderType() {
		OrderService orderService = Context.getOrderService();
		OrderType orderType = orderService.getOrderType(15);
		assertFalse(orderType.getRetired());
		assertNull(orderType.getRetiredBy());
		assertNull(orderType.getRetireReason());
		assertNull(orderType.getDateRetired());
		orderService.retireOrderType(orderType, "Retire for testing purposes");
		orderType = orderService.getOrderType(15);
		assertTrue(orderType.getRetired());
		assertNotNull(orderType.getRetiredBy());
		assertNotNull(orderType.getRetireReason());
		assertNotNull(orderType.getDateRetired());
	}
	
	/**
	 * @see {@link OrderService#unretireOrderType(org.openmrs.OrderType)}
	 */
	@Test
	@Verifies(value = "should unretire order type", method = "unretireOrderType(org.openmrs.OrderType)")
	public void unretireOrderType_shouldUnretireTheGivenUnretiredOrderType() {
		OrderService orderService = Context.getOrderService();
		OrderType orderType = orderService.getOrderType(16);
		assertTrue(orderType.getRetired());
		assertNotNull(orderType.getRetiredBy());
		assertNotNull(orderType.getRetireReason());
		assertNotNull(orderType.getDateRetired());
		orderService.unretireOrderType(orderType);
		orderType = orderService.getOrderType(16);
		assertFalse(orderType.getRetired());
		assertNull(orderType.getRetiredBy());
		assertNull(orderType.getRetireReason());
		assertNull(orderType.getDateRetired());
	}
	
	/**
	 * @see {@link OrderService#getSubtypes(org.openmrs.OrderType, boolean)}
	 */
	@Test
	@Verifies(value = "should return all order subtypes of given order type", method = "getOrderSubtypes(org.openmrs.OrderType, boolean)")
	public void getOrderSubTypes_shouldGetAllSubOrderTypesWithRetiredOrderTypes() {
		OrderService orderService = Context.getOrderService();
		List<OrderType> orderTypeList = orderService.getSubtypes(orderService.getOrderType(2), true);
		assertEquals(7, orderTypeList.size());
	}
	
	/**
	 * @see {@link OrderService#getSubtypes(org.openmrs.OrderType, boolean)}
	 */
	@Test
	@Verifies(value = "should return unretired order subtypes of given order type", method = "getOrderSubtypes(org.openmrs.OrderType, boolean)")
	public void getOrderSubTypes_shouldGetAllSubOrderTypesWithoutRetiredOrderTypes() {
		OrderService orderService = Context.getOrderService();
		List<OrderType> orderTypeList = orderService.getSubtypes(orderService.getOrderType(2), false);
		assertEquals(6, orderTypeList.size());
	}
	
	/**
	 * @verifies default to care setting and order type defined in the order context if null
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldDefaultToCareSettingAndOrderTypeDefinedInTheOrderContextIfNull() throws Exception {
		Order order = new Order();
		order.setPatient(patientService.getPatient(7));
		Concept aspirin = conceptService.getConcept(88);
		order.setConcept(aspirin);
		order.setOrderer(providerService.getProvider(1));
		order.setEncounter(encounterService.getEncounter(3));
		order.setStartDate(new Date());
		OrderType expectedOrderType = orderService.getOrderType(3);
		CareSetting expectedCareSetting = orderService.getCareSetting(1);
		OrderContext orderContext = new OrderContext();
		orderContext.setOrderType(expectedOrderType);
		orderContext.setCareSetting(expectedCareSetting);
		order = orderService.saveOrder(order, orderContext);
		assertFalse(expectedOrderType.getConceptClasses().contains(aspirin.getConceptClass()));
		assertEquals(expectedOrderType, order.getOrderType());
		assertEquals(expectedCareSetting, order.getCareSetting());
	}
	
	/**
	 * @see OrderService#getDiscontinuationOrder(Order)
	 * @verifies return discontinuation order if order has been discontinued
	 */
	@Test
	public void getDiscontinuationOrder_shouldReturnDiscontinuationOrderIfOrderHasBeenDiscontinued() throws Exception {
		Order order = orderService.getOrder(111);
		Order discontinuationOrder = orderService.discontinueOrder(order, "no reason", new Date(), providerService
		        .getProvider(1), order.getEncounter());
		
		Order foundDiscontinuationOrder = orderService.getDiscontinuationOrder(order);
		
		assertThat(foundDiscontinuationOrder, is(discontinuationOrder));
	}
	
	/**
	 * @see OrderService#getDiscontinuationOrder(Order)
	 * @verifies return null if order has not been discontinued
	 */
	@Test
	public void getDiscontinuationOrder_shouldReturnNullIfOrderHasNotBeenDiscontinued() throws Exception {
		Order order = orderService.getOrder(111);
		Order discontinuationOrder = orderService.getDiscontinuationOrder(order);
		
		assertThat(discontinuationOrder, is(nullValue()));
	}
	
	/**
	 * @see OrderService#getOrderTypeByConceptClass(ConceptClass)
	 * @verifies get order type mapped to the given concept class
	 */
	@Test
	public void getOrderTypeByConceptClass_shouldGetOrderTypeMappedToTheGivenConceptClass() throws Exception {
		OrderType orderType = orderService.getOrderTypeByConceptClass(Context.getConceptService().getConceptClass(1));
		
		Assert.assertNotNull(orderType);
		Assert.assertEquals(2, orderType.getOrderTypeId().intValue());
	}
	
	/**
	 * @see OrderService#getOrderTypeByConcept(Concept)
	 * @verifies get order type mapped to the given concept
	 */
	@Test
	public void getOrderTypeByConcept_shouldGetOrderTypeMappedToTheGivenConcept() throws Exception {
		OrderType orderType = orderService.getOrderTypeByConcept(Context.getConceptService().getConcept(5089));
		
		Assert.assertNotNull(orderType);
		Assert.assertEquals(2, orderType.getOrderTypeId().intValue());
	}
	
	/**
	 * @verifies not allow changing the patient of the previous order when revising an order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowChangingThePatientOfThePreviousOrderWhenRevisingAnOrder() throws Exception {
		Order orderToRevise = orderService.getOrder(7);
		Patient newPatient = patientService.getPatient(7);
		assertFalse(orderToRevise.getPatient().equals(newPatient));
		orderToRevise.setPatient(newPatient);
		Order order = orderToRevise.cloneForRevision();
		order.setStartDate(new Date());
		order.setEncounter(encounterService.getEncounter(3));
		order.setOrderer(providerService.getProvider(1));
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot change the patient of an order");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies not allow changing the careSetting of the previous order when revising an order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowChangingTheCareSettingOfThePreviousOrderWhenRevisingAnOrder() throws Exception {
		Order order = orderService.getOrder(7).cloneForRevision();
		order.setStartDate(new Date());
		order.setEncounter(encounterService.getEncounter(6));
		order.setOrderer(providerService.getProvider(1));
		CareSetting newCareSetting = orderService.getCareSetting(2);
		assertFalse(order.getPreviousOrder().getCareSetting().equals(newCareSetting));
		order.getPreviousOrder().setCareSetting(newCareSetting);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot change the careSetting of an order");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies not allow changing the concept of the previous order when revising an order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowChangingTheConceptOfThePreviousOrderWhenRevisingAnOrder() throws Exception {
		Order order = orderService.getOrder(7).cloneForRevision();
		order.setStartDate(new Date());
		order.setEncounter(encounterService.getEncounter(6));
		order.setOrderer(providerService.getProvider(1));
		Concept newConcept = conceptService.getConcept(5089);
		assertFalse(order.getPreviousOrder().getConcept().equals(newConcept));
		order.getPreviousOrder().setConcept(newConcept);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot change the concept of an order");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies not allow changing the drug of the previous drug order when revising an order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldNotAllowChangingTheDrugOfThePreviousDrugOrderWhenRevisingAnOrder() throws Exception {
		DrugOrder order = (DrugOrder) orderService.getOrder(111).cloneForRevision();
		order.setStartDate(new Date());
		order.setEncounter(encounterService.getEncounter(3));
		order.setOrderer(providerService.getProvider(1));
		Drug newDrug = conceptService.getDrug(2);
		DrugOrder previousOrder = (DrugOrder) order.getPreviousOrder();
		assertFalse(previousOrder.getDrug().equals(newDrug));
		previousOrder.setDrug(newDrug);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("Cannot change the drug of a drug order");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies fail if concept in previous order does not match that of the revised order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfConceptInPreviousOrderDoesNotMatchThatOfTheRevisedOrder() throws Exception {
		Order previousOrder = orderService.getOrder(7);
		Order order = previousOrder.cloneForRevision();
		order.setStartDate(new Date());
		order.setOrderer(providerService.getProvider(1));
		order.setEncounter(encounterService.getEncounter(6));
		Concept newConcept = conceptService.getConcept(5089);
		assertFalse(previousOrder.getConcept().equals(newConcept));
		order.setConcept(newConcept);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The concept of the previous order and the new one order don't match");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies fail if the existing drug order matches the concept and not drug of the revised
	 *           order
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfTheExistingDrugOrderMatchesTheConceptAndNotDrugOfTheRevisedOrder() throws Exception {
		final DrugOrder orderToDiscontinue = (DrugOrder) orderService.getOrder(5);
		
		//create a different test drug
		Drug discontinuationOrderDrug = new Drug();
		discontinuationOrderDrug.setConcept(orderToDiscontinue.getConcept());
		discontinuationOrderDrug = conceptService.saveDrug(discontinuationOrderDrug);
		assertNotEquals(discontinuationOrderDrug, orderToDiscontinue.getDrug());
		assertNotNull(orderToDiscontinue.getDrug());
		
		DrugOrder order = orderToDiscontinue.cloneForRevision();
		order.setStartDate(new Date());
		order.setOrderer(providerService.getProvider(1));
		order.setEncounter(encounterService.getEncounter(6));
		order.setDrug(discontinuationOrderDrug);
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The drug of the previous order and the new one order don't match");
		orderService.saveOrder(order, null);
	}
	
	/**
	 * @verifies fail if the order type of the previous order does not match
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfTheOrderTypeOfThePreviousOrderDoesNotMatch() throws Exception {
		Order order = orderService.getOrder(7);
		assertTrue(OrderUtilTest.isActiveOrder(order, null));
		Order discontinuationOrder = order.cloneForDiscontinuing();
		OrderType orderType = orderService.getOrderType(7);
		assertNotEquals(discontinuationOrder.getOrderType(), orderType);
		assertTrue(OrderUtil.isType(discontinuationOrder.getOrderType(), orderType));
		discontinuationOrder.setOrderType(orderType);
		discontinuationOrder.setOrderer(Context.getProviderService().getProvider(1));
		discontinuationOrder.setEncounter(Context.getEncounterService().getEncounter(6));
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The order type does not match that of the previous order");
		orderService.saveOrder(discontinuationOrder, null);
	}
	
	/**
	 * @verifies fail if the java type of the previous order does not match
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfTheJavaTypeOfThePreviousOrderDoesNotMatch() throws Exception {
		Order order = orderService.getOrder(7);
		assertTrue(OrderUtilTest.isActiveOrder(order, null));
		Order discontinuationOrder = new SomeTestOrder();
		discontinuationOrder.setCareSetting(order.getCareSetting());
		discontinuationOrder.setConcept(order.getConcept());
		discontinuationOrder.setAction(Order.Action.DISCONTINUE.DISCONTINUE);
		discontinuationOrder.setPreviousOrder(order);
		discontinuationOrder.setPatient(order.getPatient());
		assertTrue(order.getOrderType().getJavaClass().isAssignableFrom(discontinuationOrder.getClass()));
		discontinuationOrder.setOrderType(order.getOrderType());
		discontinuationOrder.setOrderer(Context.getProviderService().getProvider(1));
		discontinuationOrder.setEncounter(Context.getEncounterService().getEncounter(6));
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The class does not match that of the previous order");
		orderService.saveOrder(discontinuationOrder, null);
	}
	
	/**
	 * @verifies fail if the careSetting of the previous order does not match
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldFailIfTheCareSettingOfThePreviousOrderDoesNotMatch() throws Exception {
		Order order = orderService.getOrder(7);
		assertTrue(OrderUtilTest.isActiveOrder(order, null));
		Order discontinuationOrder = order.cloneForDiscontinuing();
		CareSetting careSetting = orderService.getCareSetting(2);
		assertNotEquals(discontinuationOrder.getCareSetting(), careSetting);
		discontinuationOrder.setCareSetting(careSetting);
		discontinuationOrder.setOrderer(Context.getProviderService().getProvider(1));
		discontinuationOrder.setEncounter(Context.getEncounterService().getEncounter(6));
		
		expectedException.expect(APIException.class);
		expectedException.expectMessage("The care setting does not match that of the previous order");
		orderService.saveOrder(discontinuationOrder, null);
	}
	
	/**
	 * @verifies set concept for drug orders if null
	 * @see OrderService#saveOrder(org.openmrs.Order, OrderContext)
	 */
	@Test
	public void saveOrder_shouldSetConceptForDrugOrdersIfNull() throws Exception {
		Patient patient = patientService.getPatient(7);
		CareSetting careSetting = orderService.getCareSetting(2);
		OrderType orderType = orderService.getOrderTypeByName("Drug order");
		
		//place drug order
		DrugOrder order = new DrugOrder();
		Encounter encounter = encounterService.getEncounter(3);
		order.setEncounter(encounter);
		order.setPatient(patient);
		order.setDrug(conceptService.getDrug(3));
		order.setCareSetting(careSetting);
		order.setOrderer(Context.getProviderService().getProvider(1));
		order.setStartDate(encounter.getEncounterDatetime());
		order.setOrderType(orderType);
		order.setDosingType(DrugOrder.DosingType.FREE_TEXT);
		order.setInstructions("None");
		
		orderService.saveOrder(order, null);
		assertNotNull(order.getOrderId());
	}
	
	/**
	 * @see org.openmrs.api.OrderService#getDrugRoutes()
	 * @verifies get drug routes associated with concept uuid provided in global properties
	 */
	@Test
	public void getDrugRoutes_shouldGetDrugRoutesAssociatedConceptPrividedInGlobalProperties() throws Exception {
		Concept drugRoutes = new Concept();
		ConceptName cn = new ConceptName("Test concept for drug routes", Locale.US);
		drugRoutes.addName(cn);
		drugRoutes.setSet(true);
		Concept concept3 = conceptService.getConcept(3);
		Concept concept4 = conceptService.getConcept(4);
		Concept concept5 = conceptService.getConcept(5);
		drugRoutes.addSetMember(concept3);
		drugRoutes.addSetMember(concept4);
		drugRoutes.addSetMember(concept5);
		drugRoutes = conceptService.saveConcept(drugRoutes);
		
		AdministrationService as = Context.getAdministrationService();
		List<GlobalProperty> globalProperties = as.getAllGlobalProperties();
		globalProperties.add(new GlobalProperty(OpenmrsConstants.DRUG_ROUTE_CONCEPT_UUID, drugRoutes.getUuid(), "test"));
		as.saveGlobalProperties(globalProperties);
		List<Concept> drugRoutesList = orderService.getDrugRoutes();
		assertEquals(3, drugRoutesList.size());
		assertTrue(drugRoutesList.contains(concept3));
		assertTrue(drugRoutesList.contains(concept4));
		assertTrue(drugRoutesList.contains(concept5));
	}
}
