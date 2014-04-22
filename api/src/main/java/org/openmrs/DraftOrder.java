package org.openmrs;

import java.util.Date;
import java.util.UUID;

/** 
 * It represents a draft of an order. It must be used to create new orders, e.g.
 * <pre>
 * DraftOrder draft = new DraftOrder(orderType, orderer, encounter).setStartDate(new Date())
 * 		.setUrgency(Urgency.ROUTINE);
 * 
 * draft.setAction(Action.REVISE);
 * 
 * Order = draft.buildOrder();
 * </pre>
 * <p>
 * Since 1.10 orders are not editable once saved so you must discontinue an order and create a new one
 * if you want to correct the discontinued order.
 * <p>
 * Note that orders are not strictly immutable as you can still call setters for auditable fields like
 * {@link Order#setCreator(User)}, {@link Order#setDateCreated(Date)}, etc. It is not advisable to do so.
 * 
 * @since 1.10
 */
public class DraftOrder extends Order implements Builder<Order> {
	
	public DraftOrder(OrderType orderType, Provider orderer, Encounter encounter) {
		this.orderType = orderType;
		this.orderer = orderer;
		this.encounter = encounter;
		this.patient = encounter.getPatient();
	}
	
	public DraftOrder(Order order) {
		super(order);
	}
	
	@Override
	public Order build() {
		return new Order(this);
	}
	
	public DraftOrder resetIdAndUuid() {
		this.orderId = null;
		setUuid(UUID.randomUUID().toString());
		
		return this;
	}
	
	/**
	 * Creates a discontinuation order for this order, sets the previousOrder and action fields,
	 * note that the discontinuation order needs to be saved for the discontinuation to take effect
	 * 
	 * @return the newly created order
	 * @since 1.10
	 * @should set all the relevant fields
	 */
	public static DraftOrder cloneForDiscontinuing(Order order) {
		DraftOrder draft = new DraftOrder(order.orderType, order.orderer, order.encounter).resetIdAndUuid();
		draft.setCareSetting(order.getCareSetting()).setConcept(order.getConcept());
		
		draft.setAction(Action.DISCONTINUE);
		draft.setPreviousOrder(order);
		
		return draft;
	}
	
	/**
	 * Creates an order for revision from this order, sets the previousOrder and action field.
	 * 
	 * @return the newly created order
	 * @since 1.10
	 * @should set all the relevant fields
	 */
	public static DraftOrder cloneForRevision(Order order) {
		DraftOrder draft = new DraftOrder(order).resetIdAndUuid();
		
		draft.setAction(Action.REVISE);
		draft.setPreviousOrder(order);
		return draft;
	}
	
	public DraftOrder setConcept(Concept concept) {
		this.concept = concept;
		return this;
	}

	public DraftOrder setAutoExpireDate(Date autoExpireDate) {
		this.autoExpireDate = autoExpireDate;
		return this;
	}
	
	public DraftOrder setScheduledDate(Date scheduledDate) {
		this.scheduledDate = scheduledDate;
		return this;
	}
	
	public DraftOrder setDateStopped(Date dateStopped) {
		this.dateStopped = dateStopped;
		return this;
	}
	
	public DraftOrder setOrderReason(Concept orderReason) {
		this.orderReason = orderReason;
		return this;
	}
	
	public DraftOrder setEncounter(Encounter encounter) {
		this.encounter = encounter;
		this.patient = encounter.getPatient();
		return this;
	}
	
	public DraftOrder setInstructions(String instructions) {
		this.instructions = instructions;
		return this;
	}
	
	public DraftOrder setAccessionNumber(String accessionNumber) {
		this.accessionNumber = accessionNumber;
		return this;
	}
	
	public DraftOrder setOrderer(Provider orderer) {
		this.orderer = orderer;
		return this;
	}

	public DraftOrder setStartDate(Date startDate) {
		this.startDate = startDate;
		return this;
	}
	
	public DraftOrder setOrderReasonNonCoded(String orderReasonNonCoded) {
		this.orderReasonNonCoded = orderReasonNonCoded;
		return this;
	}
	
	public DraftOrder setCommentToFulfiller(String commentToFulfiller) {
		this.commentToFulfiller = commentToFulfiller;
		return this;
	}

	public DraftOrder setUrgency(Urgency urgency) {
		this.urgency = urgency;
		return this;
	}
	
	public DraftOrder setPreviousOrder(Order previousOrder) {
		this.previousOrder = previousOrder;
		return this;
	}
	
	public DraftOrder setAction(Action action) {
		this.action = action;
		return this;
	}
	
	public DraftOrder setCareSetting(CareSetting careSetting) {
		this.careSetting = careSetting;
		return this;
	}
	
	public DraftOrder setOrderType(OrderType orderType) {
		this.orderType = orderType;
		return this;
	}
}
