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
package org.openmrs;

import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.order.OrderUtil;

/**
 * Dates should be interpreted as follows: If startDate is null then the order has been going on
 * "since the beginning of time" Otherwise the order starts on startDate If discontinued is non-null
 * and true, then the following fields should be ignored: autoExpireDate if dateStopped is null then
 * the order was discontinued "the instant after it began" otherwise it was given from its starting
 * date until dateStopped Otherwise (discontinued is null or false) if autoExpireDate is null, the
 * order is set to go forever otherwise the order goes until autoExpireDate the following fields
 * should be ignored: discontinuedBy dateStopped discontinuedReason It is an error to have
 * discontinued be true and have dateStopped be after autoExpireDate. However this is not checked
 * for in the database or the application.
 * 
 * @version 1.0
 */
public class Order extends BaseOpenmrsData implements java.io.Serializable {
	
	public static final long serialVersionUID = 4334343L;
	
	/**
	 * @since 1.9.2, 1.10
	 */
	public enum Urgency {
		ROUTINE, STAT, ON_SCHEDULED_DATE
	}
	
	/**
	 * @since 1.10
	 */
	public enum Action {
		NEW, REVISE, RENEW, DISCONTINUE
	}
	
	private static final Log log = LogFactory.getLog(Order.class);
	
	// Fields
	
	protected Integer orderId;
	
	protected Patient patient;
	
	protected Concept concept;
	
	protected String instructions;
	
	protected Date startDate;
	
	protected Date autoExpireDate;
	
	protected Encounter encounter;
	
	protected Provider orderer;
	
	protected Date dateStopped;
	
	protected Concept orderReason;
	
	protected String accessionNumber;
	
	protected String orderReasonNonCoded;
	
	protected Urgency urgency = Urgency.ROUTINE;
	
	protected String orderNumber;
	
	protected String commentToFulfiller;
	
	protected CareSetting careSetting;
	
	protected OrderType orderType;
	
	protected Date scheduledDate;
	
	/**
	 * Allows orders to be linked to a previous order - e.g., an order discontinue ampicillin linked
	 * to the original ampicillin order (the D/C gets its own order number)
	 */
	protected Order previousOrder;
	
	/**
	 * Represents the action being taken on an order.
	 * 
	 * @see org.openmrs.Order.Action
	 */
	protected Action action = Action.NEW;

	protected Order() {
	}
	
	public Order(Order copy) {
		super(copy);
		
		orderId = copy.orderId;
		patient = copy.patient;
		concept = copy.concept;
		instructions = copy.instructions;
		startDate = copy.startDate;
		autoExpireDate = copy.autoExpireDate;
		encounter = copy.encounter;
		orderer = copy.orderer;
		dateStopped = copy.dateStopped;
		orderReason = copy.orderReason;
		accessionNumber = copy.accessionNumber;
		orderReasonNonCoded = copy.orderReasonNonCoded;
		urgency = copy.urgency;
		orderNumber = copy.orderNumber;
		commentToFulfiller = copy.commentToFulfiller;
		careSetting = copy.careSetting;
		orderType = copy.orderType;
		scheduledDate = copy.scheduledDate;
		previousOrder = copy.previousOrder;
		action = copy.action;
	}
	
	/**
	 * Performs a shallow copy of this Order. Does NOT copy orderId.
	 * 
	 * @return a shallow copy of this Order
	 * @should copy all fields
	 */
	public Order copy() {
		return copyHelper(new Order());
	}
	
	/**
	 * The purpose of this method is to allow subclasses of Order to delegate a portion of their
	 * copy() method back to the superclass, in case the base class implementation changes.
	 * 
	 * @param target an Order that will have the state of <code>this</code> copied into it
	 * @return Returns the Order that was passed in, with state copied into it
	 */
	protected Order copyHelper(Order target) {
		target.patient = getPatient();
		target.concept = getConcept();
		target.orderType = getOrderType();
		target.instructions = getInstructions();
		target.startDate = getStartDate();
		target.autoExpireDate = getAutoExpireDate();
		target.encounter = getEncounter();
		target.orderer = getOrderer();
		target.creator = getCreator();
		target.setDateCreated(getDateCreated());
		target.dateStopped = getDateStopped();
		target.orderReason = getOrderReason();
		target.orderReasonNonCoded = getOrderReasonNonCoded();
		target.accessionNumber = getAccessionNumber();
		target.setVoided(isVoided());
		target.setVoidedBy(getVoidedBy());
		target.setDateVoided(getDateVoided());
		target.setVoidReason(getVoidReason());
		target.urgency = getUrgency();
		target.commentToFulfiller = getCommentToFulfiller();
		target.previousOrder = getPreviousOrder();
		target.action = getAction();
		target.orderNumber = getOrderNumber();
		target.careSetting = getCareSetting();
		target.setChangedBy(getChangedBy());
		target.setDateChanged(getDateChanged());
		target.scheduledDate = getScheduledDate();
		return target;
	}
	
	// Property accessors
	
	/**
	 * @return Returns the autoExpireDate.
	 */
	public Date getAutoExpireDate() {
		return autoExpireDate;
	}
	
	/**
	 * @return Returns the concept.
	 */
	public Concept getConcept() {
		return concept;
	}
	
		
	/**
	 * @return the scheduledDate
	 * @since 1.10
	 */
	public Date getScheduledDate() {
		return scheduledDate;
	}
	
	/**
	 * @return Returns the dateStopped.
	 * @since 1.10
	 */
	public Date getDateStopped() {
		return dateStopped;
	}
	
	/**
	 * @return Returns the orderReason.
	 */
	public Concept getOrderReason() {
		return orderReason;
	}
	
	/**
	 * @return Returns the encounter.
	 */
	public Encounter getEncounter() {
		return encounter;
	}
	
	/**
	 * @return Returns the instructions.
	 */
	public String getInstructions() {
		return instructions;
	}
	
	/**
	 * @return Returns the accessionNumber.
	 */
	public String getAccessionNumber() {
		return accessionNumber;
	}
	
	/**
	 * @return Returns the orderer.
	 */
	public Provider getOrderer() {
		return orderer;
	}
	
	/**
	 * @return Returns the orderId.
	 */
	public Integer getOrderId() {
		return orderId;
	}
	
	/**
	 * @return Returns the startDate.
	 */
	public Date getStartDate() {
		return startDate;
	}
	
	/**
	 * @return Returns the orderReasonNonCoded.
	 */
	public String getOrderReasonNonCoded() {
		return orderReasonNonCoded;
	}
	
	/**
	 * @return the commentToFulfiller
	 * @since 1.10
	 */
	public String getCommentToFulfiller() {
		return commentToFulfiller;
	}
	
	/**
	 * Convenience method to determine if order is current
	 * 
	 * @param checkDate - the date on which to check order. if null, will use current date
	 * @return boolean indicating whether the order was current on the input date
	 */
	public boolean isCurrent(Date checkDate) {
		if (isVoided())
			return false;
		
		if (checkDate == null) {
			checkDate = new Date();
		}
		
		if (startDate != null && checkDate.before(startDate)) {
			return false;
		}
		
		if (isDiscontinuedRightNow()) {
			if (dateStopped == null)
				return checkDate.equals(startDate);
			else
				return checkDate.before(dateStopped);
			
		} else {
			if (autoExpireDate == null)
				return true;
			else
				return checkDate.before(autoExpireDate);
		}
	}
	
	public boolean isCurrent() {
		return isCurrent(new Date());
	}
	
	public boolean isFuture(Date checkDate) {
		if (isVoided())
			return false;
		if (checkDate == null)
			checkDate = new Date();
		
		return startDate != null && checkDate.before(startDate);
	}
	
	public boolean isFuture() {
		return isFuture(new Date());
	}
	
	/**
	 * Convenience method to determine if order is discontinued at a given time
	 * 
	 * @param checkDate - the date on which to check order. if null, will use current date
	 * @return boolean indicating whether the order was discontinued on the input date
	 */
	public boolean isDiscontinued(Date checkDate) {
		if (isVoided())
			return false;
		if (checkDate == null)
			checkDate = new Date();
		
		if (startDate == null || checkDate.before(startDate)) {
			return false;
		}
		if (dateStopped != null && dateStopped.after(checkDate)) {
			return false;
		}
		if (dateStopped == null) {
			return false;
		}
		
		// guess we can't assume this has been filled correctly?
		/*
		 * if (dateStopped == null) { return false; }
		 */
		return true;
	}
	
	/*
	 * orderForm:jsp: <spring:bind path="order.discontinued" /> results in a call to
	 * isDiscontinued() which doesn't give access to the discontinued property so renamed it to
	 * isDiscontinuedRightNow which results in a call to getDiscontinued.
	 * @since 1.5
	 */
	public boolean isDiscontinuedRightNow() {
		return isDiscontinued(new Date());
	}
	
	public Patient getPatient() {
		return patient;
	}
	
	public Integer getId() {
		return getOrderId();
	}
	
	/**
	 * @see java.lang.Object#toString()
	 */
	public String toString() {
		return "Order. orderId: " + orderId + " patient: " + patient + " concept: " + concept + " care setting: "
		        + careSetting;
	}
	
	/**
	 * @since 1.5
	 * @see org.openmrs.OpenmrsObject#setId(java.lang.Integer)
	 */
	public void setId(Integer id) {
		orderId = id;
	}
	
	/**
	 * @return the urgency
	 * @since 1.9.2
	 */
	public Urgency getUrgency() {
		return urgency;
	}
	
	/**
	 * @return the orderNumber
	 * @since 1.10
	 */
	public String getOrderNumber() {
		return orderNumber;
	}
	
	/**
	 * Gets the previous related order.
	 * 
	 * @since 1.10
	 * @return the previous order.
	 */
	public Order getPreviousOrder() {
		return previousOrder;
	}
	
	/**
	 * Gets the action
	 * 
	 * @return the action
	 * @since 1.10
	 */
	public Action getAction() {
		return action;
	}
	
	/**
	 * Gets the careSetting
	 * 
	 * @return the action
	 * @since 1.10
	 */
	public CareSetting getCareSetting() {
		return careSetting;
	}
	
	/**
	 * Get the {@link org.openmrs.OrderType}
	 * 
	 * @return the {@link org.openmrs.OrderType}
	 */
	public OrderType getOrderType() {
		return orderType;
	}
	
	/**
	 * Checks whether this order's orderType matches or is a sub type of the specified one
	 * 
	 * @since 1.10
	 * @param orderType the orderType to match on
	 * @return true if the type of the order matches or is a sub type of the other order
	 * @should true if it is the same or is a subtype
	 * @should false if it neither the same nor a subtype
	 */
	public boolean isType(OrderType orderType) {
		return OrderUtil.isType(orderType, this.orderType);
	}
}
