package org.java.security;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Public Key Store implementing {@link KeyResolver} interface. Since this Key
 * Store only stores public keys, only {@link KeyPurpose#VERIFY} purpose is
 * supported.
 * 
 * @author Simon Galperin
 */
public class PublicKeyStore implements Iterable<Entry<String, PublicKey>> {
	private final Map<String, PublicKey> keyStore;

	// key store is new, therefore it is not changed
	private boolean changed = false;

	/**
	 * Create {@link PublicKeyStore} with {@link PublicKeyArchive#MEMORY}
	 * archive
	 */
	public PublicKeyStore() {
		this.keyStore = new HashMap<String, PublicKey>();
	}

	/**
	 * Add existing {@link PublicKey} with the given alias to the keystore
	 * 
	 * @param alias
	 *            Alias to be used
	 * @param key
	 *            {@link PublicKey} to add
	 */
	public synchronized void add(String alias, PublicKey key) {
		if (alias == null) {
			throw new IllegalArgumentException("Alias is required");
		}
		if (key == null) {
			throw new IllegalArgumentException("Key is required");
		}

		// only add initial key if it does not already exist
		if (keyStore.containsKey(alias)) {
			PublicKey publicKey = keyStore.get(alias);
			if (!key.equals(publicKey)) {
				keyStore.put(alias, key);
				this.changed = true;
			}
		} else {
			keyStore.put(alias, key);
			this.changed = true;
		}
	}

	/**
	 * Remove existing {@link PublicKey} with the given alias to the keystore
	 * 
	 * @param alias
	 *            Alias to be used
	 */
	public synchronized void remove(String alias) {
		PublicKey key = keyStore.remove(alias);
		if (key != null) {
			this.changed = true;
		}
	}

	/**
	 * @return Flag indicating of the keystore has changed since it was loaded
	 *         or saved
	 */
	public boolean isChanged() {
		return changed;
	}

	/**
	 * Internal method that supports marking the Key Store as unchanged (useful
	 * for {@link PublicKeyArchive} operations)
	 */
	protected void setChanged(boolean changed) {
		this.changed = changed;
	}

	/**
	 * Method to remove all keys from the key store.
	 */
	public synchronized void clear() {
		this.keyStore.clear();
		this.changed = true;
	}

	/**
	 * Method used to identify the {@link PublicKey} by the key alias
	 * 
	 * @param alias
	 *            alias of the key to return
	 * @return {@link PublicKey} or null in case {@link PublicKey} cannot be
	 *         identified.
	 */
	public PublicKey findKey(String alias) {
		if (alias == null) {
			throw new IllegalArgumentException("Alias may not be null");
		}

		synchronized (this) {
			return keyStore.get(alias);
		}
	}

	/**
	 * Support ability to iterate over all keys in the keystore
	 * 
	 * @see java.lang.Iterable#iterator()
	 */
	@Override
	public synchronized Iterator<Entry<String, PublicKey>> iterator() {
		final Iterator<Entry<String, PublicKey>> iterator = keyStore.entrySet().iterator();

		// create an imutable iterator
		return new Iterator<Map.Entry<String,PublicKey>>() {
			@Override
			public boolean hasNext() { return iterator.hasNext(); }
			@Override
			public Entry<String, PublicKey> next() { return iterator.next(); }
			@Override
			public void remove() {}
		};
	}
}
