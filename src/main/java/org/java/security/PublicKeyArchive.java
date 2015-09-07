package org.java.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * Interface that support archiving and reading key stores
 * 
 * @author Simon Galperin
 */
public interface PublicKeyArchive {
	/**
	 * Store all public keys from given {@link PublicKeyStore} into this archive
	 * 
	 * @param keyStore
	 *            {@link PublicKeyStore} to store
	 * @throws IOException
	 *             In case keyStore cannot be stored
	 */
	public void store(PublicKeyStore keyStore) throws IOException;

	/**
	 * Load all public keys from this archive into given {@link PublicKeyStore}
	 * 
	 * @param keyStore
	 *            {@link PublicKeyStore} to load
	 * @throws IOException
	 *             In case keyStore cannot be stored
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void load(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * Upddate (reload) new keys from this archive into the given
	 * {@link PublicKey}. This method should not remove any existing keys, only
	 * update.
	 * 
	 * @param keyStore
	 *            {@link PublicKeyStore} to update
	 * @throws IOException
	 *             In case keyStore cannot be stored
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public void update(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * Default in-memory ("Do nothing") {@link PublicKeyArchive}
	 */
	public static final PublicKeyArchive MEMORY = new PublicKeyArchive() {
		
		@Override
		public void store(PublicKeyStore keyStore) throws IOException { }
		
		@Override
		public void load(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { }

		@Override
		public void update(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { }
	};
	

}
