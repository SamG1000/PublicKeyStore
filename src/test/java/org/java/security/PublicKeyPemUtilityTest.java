package org.java.security;

import static org.junit.Assert.*;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class PublicKeyPemUtilityTest {
	private static PublicKey publicKey;
	
	@BeforeClass
	public static void createKey() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		
		KeyPair keyPair1 = generator.generateKeyPair();
		publicKey = keyPair1.getPublic();
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testReadWriteKey() throws Exception {
		StringWriter writer = new StringWriter();
		
		PublicKeyPemUtility.writeKey(writer, publicKey);
		
		String pem = writer.toString();
		
		StringReader reader = new StringReader(pem);
		
		PublicKey actual = PublicKeyPemUtility.readKey(reader, "RSA");
		
		assertEquals(publicKey, actual);
	}

	@Test(expected=InvalidKeySpecException.class)
	public void testReadKeyMissingPrefix() throws Exception {
		StringWriter writer = new StringWriter();
		
		PublicKeyPemUtility.writeKey(writer, publicKey);
		
		String pem = writer.toString();
		pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
		
		StringReader reader = new StringReader(pem);
		
		PublicKeyPemUtility.readKey(reader, "RSA");
	}

	@Test(expected=InvalidKeySpecException.class)
	public void testReadKeyMissingSuffix() throws Exception {
		StringWriter writer = new StringWriter();
		
		PublicKeyPemUtility.writeKey(writer, publicKey);
		
		String pem = writer.toString();
		pem = pem.replace("-----END PUBLIC KEY-----", "");
		
		StringReader reader = new StringReader(pem);
		
		PublicKeyPemUtility.readKey(reader, "RSA");
	}
	
	@Test
	public void testClass() throws Exception {
		new PublicKeyPemUtility() {};
	}
	
}
