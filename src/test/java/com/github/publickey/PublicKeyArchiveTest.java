package com.github.publickey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.github.publickey.PublicKeyArchive;
import com.github.publickey.PublicKeyStore;

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
