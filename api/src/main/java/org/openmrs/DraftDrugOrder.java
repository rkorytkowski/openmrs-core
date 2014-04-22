package org.openmrs;

import java.util.Date;
import java.util.UUID;


public class DraftDrugOrder extends DrugOrder {
	
	public DraftDrugOrder(OrderType orderType, Provider orderer, Encounter encounter) {
		this.orderType = orderType;
		this.orderer = orderer;
		this.encounter = encounter;
		this.patient = encounter.getPatient();
	}
	
	public DraftDrugOrder(DrugOrder order) {
		super(order);
	}
	
	public DrugOrder buildDrugOrder() {
		return new DrugOrder(this);
	}
	
	public DraftDrugOrder resetIdAndUuid() {
		this.orderId = null;
		setUuid(UUID.randomUUID().toString());
		
		return this;
	}
	
	/**
	 * @should set all the relevant fields
	 * @since 1.10
	 */
	public static DraftDrugOrder cloneForDiscontinuing(DrugOrder order) {
		DraftDrugOrder draft = new DraftDrugOrder(order.orderType, order.orderer, order.encounter);
		draft.setAction(Action.DISCONTINUE);
		draft.setPreviousOrder(order);
		draft.setDrug(order.getDrug());
		return draft;
	}
	
	/**
	 * Creates a DrugOrder for revision from this order, sets the previousOrder, action field and
	 * other drug order fields.
	 * 
	 * @return the newly created order
	 * @since 1.10
	 * @should set all the relevant fields
	 */
	public DraftDrugOrder cloneForRevision(DrugOrder order) {
		DraftDrugOrder draft = new DraftDrugOrder(order);
		draft.setAction(Action.REVISE);
		draft.setPreviousOrder(order);
		return draft;
	}
	
	public DraftDrugOrder setConcept(Concept concept) {
		this.concept = concept;
		return this;
	}

	public DraftDrugOrder setAutoExpireDate(Date autoExpireDate) {
		this.autoExpireDate = autoExpireDate;
		return this;
	}
	
	public DraftDrugOrder setScheduledDate(Date scheduledDate) {
		this.scheduledDate = scheduledDate;
		return this;
	}
	
	public DraftDrugOrder setDateStopped(Date dateStopped) {
		this.dateStopped = dateStopped;
		return this;
	}
	
	public DraftDrugOrder setOrderReason(Concept orderReason) {
		this.orderReason = orderReason;
		return this;
	}
	
	public DraftDrugOrder setEncounter(Encounter encounter) {
		this.encounter = encounter;
		this.patient = encounter.getPatient();
		return this;
	}
	
	public DraftDrugOrder setInstructions(String instructions) {
		this.instructions = instructions;
		return this;
	}
	
	public DraftDrugOrder setAccessionNumber(String accessionNumber) {
		this.accessionNumber = accessionNumber;
		return this;
	}
	
	public DraftDrugOrder setOrderer(Provider orderer) {
		this.orderer = orderer;
		return this;
	}

	public DraftDrugOrder setStartDate(Date startDate) {
		this.startDate = startDate;
		return this;
	}
	
	public DraftDrugOrder setOrderReasonNonCoded(String orderReasonNonCoded) {
		this.orderReasonNonCoded = orderReasonNonCoded;
		return this;
	}
	
	public DraftDrugOrder setCommentToFulfiller(String commentToFulfiller) {
		this.commentToFulfiller = commentToFulfiller;
		return this;
	}

	public DraftDrugOrder setUrgency(Urgency urgency) {
		this.urgency = urgency;
		return this;
	}
	
	public DraftDrugOrder setPreviousOrder(Order previousOrder) {
		this.previousOrder = previousOrder;
		return this;
	}
	
	public DraftDrugOrder setAction(Action action) {
		this.action = action;
		return this;
	}
	
	public DraftDrugOrder setCareSetting(CareSetting careSetting) {
		this.careSetting = careSetting;
		return this;
	}
	
	public DraftDrugOrder setOrderType(OrderType orderType) {
		this.orderType = orderType;
		return this;
	}
}
