package org.openmrs.api;

import java.io.IOException;
import java.io.InputStream;
import java.util.stream.Stream;

interface StorageService extends OpenmrsService {

	enum Tag {
		BACKUP,
		NO_BACKUP,
		REPLICATE,
		NO_REPLICA,
		ASYNC_REPLICA,
		TEMP
	}

	/**
	 * Get InputStream to read data for the given key.
	 *
	 * @param key unique key
	 * @return data
	 * @throws IOException wrong key or IO error
	 */
	InputStream getData(String key) throws IOException;

	/**
	 * Returns keys starting with the given prefix (the order depends on the implementation).
	 *
	 * @param prefix key prefix
	 * @return stream of keys
	 * @throws IOException IO error
	 */
	Stream<String> getKeys(String prefix) throws IOException;

	/**
	 * Saves the given InputStream with default tags: BACKUP, REPLICATE
	 *
	 * @param inputStream data
	 * @return unique key
	 * @throws IOException IO error
	 */
	String saveData(InputStream inputStream) throws IOException;

	/**
	 * Saves the given InputStream with the given tags.
	 *
	 * @param inputStream data
	 * @param tags tags
	 * @return unique key
	 * @throws IOException IO error
	 */
	String saveData(InputStream inputStream, Tag... tags) throws IOException;

	/**
	 * Saves the given InputStream with default tags: TEMP, NO_BACKUP, NO_REPLICA.
	 * Temporary files are kept if possible in local storage for fast IO.
	 *
	 * @param inputStream data
	 * @return unique key
	 * @throws IOException IO error
	 */
	String saveTempData(InputStream inputStream) throws IOException;

	/**
	 * Saves the given InputStream under the given key with default tags: BACKUP, REPLICATE.
	 *
	 * @param inputStream data
	 * @param key unique key
	 * @throws IOException if key exists or IO error
	 */
	void saveData(InputStream inputStream, String key) throws IOException;

	/**
	 * Saves the given InputStream with the given key and default tags: BACKUP, REPLICATE.
	 *
	 * @param inputStream data
	 * @param key unique key
	 * @throws IOException if key exists or IO error
	 */
	void saveData(InputStream inputStream, String key, Tag... tags) throws IOException;

	/**
	 * Saves the given InputStream with the given key and default tags: TEMP, NO_BACKUP, NO_REPLICA.
	 * Temporary files are kept if possible in local storage for fast IO.
	 *
	 * @param inputStream data
	 * @param key unique key
	 * @throws IOException if key exists or IO error
	 */
	void saveTempData(InputStream inputStream, String key) throws IOException;

	/**
	 * Marks data for deletion. The key may be freed up after some period.
	 *
	 * @param key unique key
	 * @return true if marked for deletion
	 * @throws IOException wrong key or IO error
	 */
	boolean purgeData(String key) throws IOException;

	boolean exists(String key);

	boolean waitUntilExists(String key);

	boolean waitUntilExists(String key, long timeout);
}
