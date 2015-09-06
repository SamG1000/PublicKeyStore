package java.security;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Objects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;

/**
 * Public Key Store implementing {@link KeyResolver} interface. Since this Key
 * Store only stores public keys, only {@link KeyPurpose#VERIFY} purpose is
 * supported.
 * 
 * @author Simon Galperin
 */
public class PublicKeyStore implements Iterable<Entry<String, PublicKey>> {
	private final static Logger log = LoggerFactory.getLogger(PublicKeyStore.class);

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
		// only add initial key if it does not already exist
		if (keyStore.containsKey(alias)) {
			PublicKey publicKey = keyStore.get(alias);
			if (!Objects.equal(key, publicKey)) {
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
		if (Strings.isNullOrEmpty(alias)) {
			if (log.isWarnEnabled()) {
				log.warn("Key name can't be null, failed to resolve the key");
			}
			return null;
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
		ImmutableMap<String, PublicKey> map = ImmutableMap.copyOf(keyStore);
		return map.entrySet().iterator();
	}
}
