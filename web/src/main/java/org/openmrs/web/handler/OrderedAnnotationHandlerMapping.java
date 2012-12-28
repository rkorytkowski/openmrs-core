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
package org.openmrs.web.handler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.openmrs.annotation.Handler;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.util.ObjectUtils;
import org.springframework.web.servlet.mvc.annotation.DefaultAnnotationHandlerMapping;

/**
 * Supports overwriting URL handlers by annotating them with {@link Handler} and specifying the
 * order parameter.
 */
public class OrderedAnnotationHandlerMapping extends DefaultAnnotationHandlerMapping {
	
	private boolean detectHandlersInAncestorContexts = false;
	
	/**
	 * @see org.springframework.web.servlet.handler.AbstractDetectingUrlHandlerMapping#setDetectHandlersInAncestorContexts(boolean)
	 */
	@Override
	public void setDetectHandlersInAncestorContexts(boolean detectHandlersInAncestorContexts) {
		super.setDetectHandlersInAncestorContexts(detectHandlersInAncestorContexts);
	}
	
	/**
	 * @see org.springframework.web.servlet.handler.AbstractDetectingUrlHandlerMapping#detectHandlers()
	 */
	@Override
	protected void detectHandlers() throws BeansException {
		if (logger.isDebugEnabled()) {
			logger.debug("Looking for URL mappings in application context: " + getApplicationContext());
		}
		String[] beanNames = (this.detectHandlersInAncestorContexts ? BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
		    getApplicationContext(), Object.class) : getApplicationContext().getBeanNamesForType(Object.class));
		
		Map<String, OrderHandler> urlsToHandlers = new HashMap<String, OrderHandler>();
		
		ApplicationContext context = getApplicationContext();
		
		// Take any bean name that we can determine URLs for.
		for (String beanName : beanNames) {
			String[] urls = determineUrlsForHandler(beanName);
			if (ObjectUtils.isEmpty(urls)) {
				continue;
			}
			
			Handler handlerAnnotation = context.findAnnotationOnBean(beanName, Handler.class);
			
			for (String url : urls) {
				OrderHandler orderHandler = urlsToHandlers.get(url);
				
				if (orderHandler != null && handlerAnnotation != null) {
					if (orderHandler.order < handlerAnnotation.order()) {
						urlsToHandlers.put(url, new OrderHandler(beanName, handlerAnnotation.order()));
					}
				} else if (orderHandler == null) {
					int order = 0;
					if (handlerAnnotation != null) {
						order = handlerAnnotation.order();
					}
					urlsToHandlers.put(url, new OrderHandler(beanName, order));
				}
			}
		}
		
		Map<String, List<String>> beansToUrls = new HashMap<String, List<String>>();
		
		for (Entry<String, OrderHandler> urlToHandler : urlsToHandlers.entrySet()) {
			List<String> urls = beansToUrls.get(urlToHandler.getValue().beanName);
			if (urls == null) {
				urls = new ArrayList<String>();
				beansToUrls.put(urlToHandler.getValue().beanName, urls);
			}
			urls.add(urlToHandler.getKey());
		}
		
		String[] emptyArray = new String[0];
		for (Entry<String, List<String>> beanToUrls : beansToUrls.entrySet()) {
			registerHandler(beanToUrls.getValue().toArray(emptyArray), beanToUrls.getKey());
		}
		
	}
	
	private static class OrderHandler {
		
		public final String beanName;
		
		public final int order;
		
		public OrderHandler(String beanName, int order) {
			this.beanName = beanName;
			this.order = order;
		}
	}
}
