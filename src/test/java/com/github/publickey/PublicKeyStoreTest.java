package com.github.publickey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.github.publickey.PublicKeyStore;

public class PublicKeyStoreTest {
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
	public void setUp() throws Exception {
		keyStore = new PublicKeyStore();
	}
	
	@Test
	public void testPublicKeyStore() throws Exception {
		PublicKeyStore keyStore = new PublicKeyStore();
		keyStore.add("expected1", expected1);
		keyStore.add("expected2", expected1);
	}
	
	@Test
	public void testAdd() throws Exception {
		keyStore.add("test", expected1);
		
		PublicKey actual = keyStore.findKey("test");
		assertEquals(expected1, actual);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testAddNullAlias() throws Exception {
		keyStore.add(null, null);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testAddNullKey() throws Exception {
		keyStore.add("test", null);
	}

	@Test
	public void testAddDuplicate() throws Exception {
		keyStore.add("test", expected1);
		
		PublicKey actual = keyStore.findKey("test");
		assertEquals(expected1, actual);

		keyStore.add("test", expected1);
		actual = keyStore.findKey("test");
		assertEquals(expected1, actual);
		
		assertEquals(1, size(keyStore));
	}

	@Test
	public void testAddOverride() throws Exception {
		keyStore.add("test", expected1);
		
		PublicKey actual = keyStore.findKey("test");
		assertEquals(expected1, actual);

		keyStore.add("test", expected2);
		actual = keyStore.findKey("test");
		assertEquals(expected2, actual);
		
		assertEquals(1, size(keyStore));
	}
	
	@Test
	public void testFindKey() throws Exception {
		keyStore.add("test", expected1);
		PublicKey actual = keyStore.findKey("test");
		assertEquals(expected1, actual);
	}

	@Test(expected=IllegalArgumentException.class)
	public void testFindKeyNull() throws Exception {
		keyStore.findKey(null);
	}

	@Test
	public void testIterator() throws Exception {
		keyStore.add("test1", expected1);
		keyStore.add("test2", expected1);
	
		for (Entry<String, PublicKey> key : keyStore) {
			assertEquals(expected1, key.getValue());
		}
		
		assertEquals(2, size(keyStore));
	}
	
	@Test
	public void testRemove() throws Exception {
		keyStore.add("test", expected1);
		
		PublicKey actual = keyStore.findKey("test");
		assertEquals(expected1, actual);

		keyStore.remove("test");
		assertNull(keyStore.findKey("test"));
		
	}

	@Test
	public void testRemoveUnknown() throws Exception {
		assertFalse(keyStore.isChanged());
		keyStore.remove("unknown");
		assertFalse(keyStore.isChanged());
	}

	@Test
	public void testIsChanged() throws Exception {
		assertFalse(keyStore.isChanged());
		keyStore.setChanged(true);
		assertTrue(keyStore.isChanged());
		keyStore.setChanged(false);
		assertFalse(keyStore.isChanged());
	}

	private final static int size(Iterable<?> iterable) {
		int counter = 0;
		
		Iterator<?> iterator= iterable.iterator();
		while(iterator.hasNext()) {
			counter++;
			iterator.next();
		}

		// make sure remove does not do anything
		iterator.remove();

		return counter;
	}
}
