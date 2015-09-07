package org.java.security;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class PublicKeyZipArchiveTest {
	private static PublicKey expected1;
	private static PublicKey expected2;
	
	private PublicKeyStore keyStore;
	
	@BeforeClass
	public static void createKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair1 = generator.generateKeyPair();
		expected1 = keyPair1.getPublic();
		
		KeyPair keyPair2 = generator.generateKeyPair();
		expected2 = keyPair2.getPublic();
	}

	@Before
	public void createKeyStore() {
		keyStore = new PublicKeyStore();
		keyStore.add("key1", expected1);
		keyStore.add("key2", expected2);
	}
	
	@Test
	public void testStoreLoad() throws Exception {
		File file = File.createTempFile(PublicKeyZipArchiveTest.class.getSimpleName() + "-", ".pubar");
		file.deleteOnExit();
		
		PublicKeyZipArchive archive = new PublicKeyZipArchive(file.getAbsolutePath());
		archive.store(keyStore);
		
		PublicKeyStore keyStore = new PublicKeyStore();
		archive.load(keyStore);

		assertEquals(expected1, keyStore.findKey("key1"));
		assertEquals(expected2, keyStore.findKey("key2"));
	}

	@Test(expected=FileNotFoundException.class)
	public void testLoadNotFound() throws Exception {
		PublicKeyZipArchive archive = new PublicKeyZipArchive("fake");
		
		PublicKeyStore keyStore = new PublicKeyStore();
		archive.load(keyStore);
	}

	@Test(expected=IOException.class)
	public void testStoreNotFound() throws Exception {
		PublicKeyZipArchive archive = new PublicKeyZipArchive("/invalid/path");
		
		PublicKeyStore keyStore = new PublicKeyStore();
		archive.store(keyStore);
	}
	

	@Test(expected=IllegalArgumentException.class)
	public void testInvalidPath() throws Exception {
		new PublicKeyZipArchive("::invalid::path");
	}
}
