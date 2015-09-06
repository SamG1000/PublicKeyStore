package java.security;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
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
	 * Load given file path as a PEM string looking for a RSA Public Key.
	 * 
	 * @param path
	 *            The file path of the Base 64 encoded RSA Public Key (as listed
	 *            above)
	 * @return instance of {@link PublicKey}
	 * @throws InvalidKeySpecException
	 *             if the given key specification is inappropriate for this key
	 *             factory to produce a public key.
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a KeyFactorySpi implementation for
	 *             the specified algorithm.
	 */
	public static PublicKey readKey(File path) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		return readKey(new FileReader(path), "RSA");
	}

	/**
	 * Parse PEM string looking for a public key.
	 * 
	 * @param pem
	 *            The Base 64 encoded Public Key (as listed above)
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
	public static PublicKey extractKey(String pem, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		return readKey(new StringReader(pem), algorithm);
	}

	/**
	 * Load given classpath file as a PEM string looking for a RSA Public Key.
	 * 
	 * @param path
	 *            The file path of the Base 64 encoded RSA Public Key (as listed
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
	public static PublicKey readKey(String classpath, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException,
			IOException {
		ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
		Reader reader = new InputStreamReader(classLoader.getResourceAsStream(classpath));
		return readKey(reader, algorithm);
	}

	/**
	 * Parse PEM string looking for a public key.
	 * 
	 * @param pem
	 *            The Base 64 encoded Public Key (as listed above)
	 * @param algorithm
	 *            The algorithm of the key
	 * @return instance of {@link PublicKey}
	 * @throws IOException
	 */
	public static void writeKey(PublicKey publicKey, Writer writer) throws IOException {
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
	 * Load given file path as a PEM string looking for a public key.
	 * 
	 * @param path
	 *            The file path of the Base 64 encoded Public Key (as listed
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
		Scanner scanner = new Scanner(reader);
		try {
			scanner.useDelimiter("\n");

			StringBuilder builder = new StringBuilder();
			
			String line = scanner.next();
	
			// remove PREFIX if any
			if (line.equals(PUBLIC_KEY_PREFIX)) {
				line = scanner.next();
			} else {
				builder.append(line);
			}
			
			while (scanner.hasNext()) {
				line = scanner.next();
				if (line.equals(PUBLIC_KEY_SUFFIX)) {
					break;
				}
				builder.append(scanner.next());
			}
			
			// all whitespace if any
			String pem = builder.toString().replaceAll("\\s", "");
	
			// generated public key
			return generatePublicKey(pem, algorithm);
		} finally {
			scanner.close();
		}
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
