package org.java.security;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

/**
 * Utility class responsible for paring ".pem" or ".pub" files that have base-64
 * encoded Public Keys. The key should be in the following format:
 * 
 * <code>
 * -----BEGIN PUBLIC KEY-----
 * <<Base 64 encoded Public Key>>
 * -----END PUBLIC KEY-----
 * <code>
 * 
 * @author Simon Galperin
 */
public abstract class PublicKeyPemUtility {
	private final static String PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----";
	private final static String PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

	/**
	 * Write Public Key in PEM format to the writer.
	 * 
	 * @param writer
	 * 			Output writer
	 * @param publicKey
	 *            Public key to store
	 * @throws IOException
	 */
	public static void writeKey(Writer writer, PublicKey publicKey) throws IOException {
		writer.write(PUBLIC_KEY_PREFIX);
		writer.write('\n');
		String base64 = generateBase64(publicKey);
		char[] charArray = base64.toCharArray();
		
		for (int i = 0; i < charArray.length; i+=64) {
			int length = Math.min(charArray.length - i, 64);
			writer.write(charArray, i, length);
			writer.write('\n');
		}
		writer.write(PUBLIC_KEY_SUFFIX);
		writer.write("\n");
	}

	/**
	 * Load PEM string from the reader and extract the public key.
	 * 
	 * @param reader
	 *            Reader contining Base 64 encoded Public Key (as listed
	 *            above)
	 * @param algorithm
	 *            The algorithm of the key
	 * @return instance of {@link PublicKey}
	 * @throws InvalidKeySpecException
	 *             if the given key specification is inappropriate for this key
	 *             factory to produce a public key.
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyFactorySpi implementation for
	 *             the specified algorithm.
	 */
	public static PublicKey readKey(Reader reader, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		@SuppressWarnings("resource")
		Scanner scanner = new Scanner(reader);
		
		scanner.useDelimiter("\n");

		StringBuilder builder = new StringBuilder();

		boolean prefixFound = false;

		String line;
		while (scanner.hasNext()) {
			line = scanner.next();
			if (line.equals(PUBLIC_KEY_PREFIX)) {
				prefixFound = true;
				break;
			}
		}

		if (!prefixFound) {
			throw new InvalidKeySpecException("Missing " + PUBLIC_KEY_PREFIX);
		}
		
		boolean suffixFound = false;
		while (scanner.hasNext()) {
			line = scanner.next();
			if (line.equals(PUBLIC_KEY_SUFFIX)) {
				suffixFound = true;
				break;
			}
			builder.append(line);
		}

		if (!suffixFound) {
			throw new InvalidKeySpecException("Missing " + PUBLIC_KEY_SUFFIX);
		}

		// all whitespace if any
		String pem = builder.toString().replaceAll("\\s", "");

		// generated public key
		return generatePublicKey(pem, algorithm);
	}

	private static PublicKey generatePublicKey(String base64, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyfactory = KeyFactory.getInstance(algorithm);
		byte[] data = DatatypeConverter.parseBase64Binary(base64);
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(data);
		return keyfactory.generatePublic(keyspec);
	}

	private static String generateBase64(PublicKey publicKey) {
		return DatatypeConverter.printBase64Binary(publicKey.getEncoded());
	}
}
