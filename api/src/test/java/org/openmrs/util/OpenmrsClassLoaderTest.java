package org.openmrs.util;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashSet;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.openmrs.Concept;
import org.openmrs.module.ModuleClassLoader;

public class OpenmrsClassLoaderTest {
	
	OpenmrsClassLoader originalClassLoader = null;
	OpenmrsClassLoader testClassLoader = null;
	
	@Before
	public void saveOriginalClassLoader() throws IOException {
		originalClassLoader = OpenmrsClassLoader.getInstance();
		testClassLoader = new OpenmrsClassLoader();
	}
	
	@After
	public void revertOriginalClassLoader() throws IOException {
		testClassLoader.close();
		OpenmrsClassLoader.setInstance(originalClassLoader);
	}
	
	/**
	 * @see OpenmrsClassLoader#deleteOldLibCaches(java.io.File)
	 * @verifies return current cache folders
	 */
	@Test
	public void deleteOldLibCaches_shouldReturnOnlyCurrentCacheFolders() throws Exception {
		FilenameFilter cacheDirFilter = new FilenameFilter() {
			
			@Override
			public boolean accept(File dir, String name) {
				return name.endsWith(".openmrs-lib-cache");
			}
		};
		//create old caches
		File oldCache = new File(System.getProperty("java.io.tmpdir"), "001.openmrs-lib-cache");
		File olderCache = new File(System.getProperty("java.io.tmpdir"), "2001.openmrs-lib-cache");
		oldCache.mkdirs();
		olderCache.mkdirs();
		File currentCache = new File(System.getProperty("java.io.tmpdir"), "002.openmrs-lib-cache");
		//create current cache folder
		currentCache.mkdirs();
		File tempDir = currentCache.getParentFile();
		int beforeDelete = tempDir.listFiles(cacheDirFilter).length;
		OpenmrsClassLoader.deleteOldLibCaches(currentCache);
		int afterDelete = tempDir.listFiles(cacheDirFilter).length;
		//verify after deleting only one cache should exist
		if (beforeDelete > 1)
			Assert.assertTrue(beforeDelete > afterDelete);
	}
	
	/**
	 * @see OpenmrsClassLoader#loadClass(String,boolean)
	 * @verifies load class from cache second time
	 */
	@Test
	public void loadClass_shouldLoadClassFromCacheSecondTime() throws Exception {
		//given
		String className = "org.openmrs.test.SomeTestClass";
		
		ModuleClassLoader moduleClassLoader = mock(ModuleClassLoader.class);
		doReturn(OpenmrsClassLoader.class).when(moduleClassLoader).loadClass(className);
		
		OpenmrsClassLoader openmrsClassLoader = spy(OpenmrsClassLoader.getInstance());
		when(openmrsClassLoader.getModuleClassLoadersForPackage("org.openmrs.test")).thenReturn(
		    new LinkedHashSet<ModuleClassLoader>(Arrays.asList(moduleClassLoader)));
		
		//when
		Class<?> classLoadedFirst = openmrsClassLoader.loadClass(className);
		Class<?> classLoadedSecond = openmrsClassLoader.loadClass(className);
		
		//then
		verify(moduleClassLoader, times(1)).loadClass(className);
		assertThat(classLoadedFirst == classLoadedSecond, is(true));
	}
	
	/**
	 * @see OpenmrsClassLoader#loadClass(String,boolean)
	 * @verifies not load class from cache if class loader has been disposed
	 */
	@Test
	public void loadClass_shouldNotLoadClassFromCacheIfClassLoaderHasBeenDisposed() throws Exception {
		//given
		String className = "org.openmrs.test.SomeTestClass";
		
		ModuleClassLoader moduleClassLoader = mock(ModuleClassLoader.class);
		doReturn(OpenmrsClassLoader.class).when(moduleClassLoader).loadClass(className);
		
		OpenmrsClassLoader openmrsClassLoader = spy(OpenmrsClassLoader.getInstance());
		when(openmrsClassLoader.getModuleClassLoadersForPackage("org.openmrs.test")).thenReturn(
		    new LinkedHashSet<ModuleClassLoader>(Arrays.asList(moduleClassLoader)));
		
		//when
		Class<?> classLoadedFirst = openmrsClassLoader.loadClass(className);
		
		when(moduleClassLoader.isDisposed()).thenReturn(true);
		
		ModuleClassLoader newModuleClassLoader = mock(ModuleClassLoader.class);
		doReturn(OpenmrsClassLoader.class).when(newModuleClassLoader).loadClass(className);
		when(openmrsClassLoader.getModuleClassLoadersForPackage("org.openmrs.test")).thenReturn(
		    new LinkedHashSet<ModuleClassLoader>(Arrays.asList(moduleClassLoader, newModuleClassLoader)));
		
		Class<?> classLoadedSecond = openmrsClassLoader.loadClass(className);
		
		//then
		verify(moduleClassLoader, times(1)).loadClass(className);
		verify(newModuleClassLoader, times(1)).loadClass(className);
		assertThat(classLoadedFirst == classLoadedSecond, is(false));
	}
	
	/**
	 * @see OpenmrsClassLoader#loadClass(String,boolean)
	 * @verifies load class from parent first
	 */
	@Test
	public void loadClass_shouldLoadClassFromParentFirst() throws Exception {
		//given
		String className = "org.openmrs.Concept";
		
		ModuleClassLoader moduleClassLoader = mock(ModuleClassLoader.class);
		doReturn(OpenmrsClassLoader.class).when(moduleClassLoader).loadClass(className);
		
		OpenmrsClassLoader openmrsClassLoader = spy(OpenmrsClassLoader.getInstance());
		when(openmrsClassLoader.getModuleClassLoadersForPackage("org.openmrs")).thenReturn(
		    new LinkedHashSet<ModuleClassLoader>(Arrays.asList(moduleClassLoader)));
		
		//when
		Class<?> classLoaded = openmrsClassLoader.loadClass(className);
		
		//then
		verify(moduleClassLoader, never()).loadClass(className);
		assertThat(classLoaded == Concept.class, is(true));
	}
	
	/**
	 * @see OpenmrsClassLoader#loadClass(String,boolean)
	 * @verifies load class if two module class loaders have same packages
	 */
	@SuppressWarnings("unchecked")
    @Test
	public void loadClass_shouldLoadClassIfTwoModuleClassLoadersHaveSamePackages() throws Exception {
		//given
		String className = "org.openmrs.test.SomeTestClass";
		
		ModuleClassLoader moduleClassLoader = mock(ModuleClassLoader.class);
		doReturn(OpenmrsClassLoader.class).when(moduleClassLoader).loadClass(className);
		
		ModuleClassLoader otherModuleClassLoader = mock(ModuleClassLoader.class);
		when(otherModuleClassLoader.loadClass(className)).thenThrow(ClassNotFoundException.class);
		
		OpenmrsClassLoader openmrsClassLoader = spy(OpenmrsClassLoader.getInstance());
		when(openmrsClassLoader.getModuleClassLoadersForPackage("org.openmrs.test")).thenReturn(
		    new LinkedHashSet<ModuleClassLoader>(Arrays.asList(moduleClassLoader, otherModuleClassLoader)));
		
		//when
		Class<?> classLoaded = openmrsClassLoader.loadClass(className);
		
		//then
		verify(moduleClassLoader, times(1)).loadClass(className);
		assertThat(classLoaded == OpenmrsClassLoader.class, is(true));
	}
}
