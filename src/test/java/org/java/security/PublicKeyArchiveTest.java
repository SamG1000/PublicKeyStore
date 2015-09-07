package org.java.security;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PublicKeyArchiveTest {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testPublicKeyArchiveMemory() throws Exception {
		PublicKeyStore empty = new PublicKeyStore();
		PublicKeyArchive archive = PublicKeyArchive.MEMORY;
		archive.load(empty);
		archive.store(empty);
		archive.update(empty);
	}
}
