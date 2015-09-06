package java.security;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Splitter;
import com.google.common.io.BaseEncoding;
import com.google.common.io.CharStreams;

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
	private final static Logger logger = LoggerFactory.getLogger(PublicKeyPemUtility.class);
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
	public static PublicKey readKey(Reader reader, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		String pem = CharStreams.toString(reader);
		return extractKey(pem, algorithm);
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
		writer.append(PUBLIC_KEY_PREFIX).append("\n");
		String base64 = generateBase64(publicKey);
		Iterable<String> lines = Splitter.fixedLength(64).split(base64);
		for (String line : lines) {
			writer.append(line).append('\n');
		}
		writer.append(PUBLIC_KEY_SUFFIX).append("\n");
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
		// remove PREFIX if any
		if (pem.contains(PUBLIC_KEY_PREFIX)) {
			pem = pem.replaceAll(PUBLIC_KEY_PREFIX, "");
		} else {
			logger.warn("Missing " + PUBLIC_KEY_PREFIX);
		}
		// remove SUFFIX if any
		if (pem.contains(PUBLIC_KEY_SUFFIX)) {
			pem = pem.replaceAll(PUBLIC_KEY_SUFFIX, "");
		} else {
			logger.warn("Missing " + PUBLIC_KEY_SUFFIX);
		}
		// all whitespace if any
		pem = pem.replaceAll("\\s", "");

		// generated public key
		return generatePublicKey(pem, algorithm);
	}

	private static PublicKey generatePublicKey(String base64, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyfactory = KeyFactory.getInstance(algorithm);

		byte[] data = BaseEncoding.base64().decode(base64);
		X509EncodedKeySpec keyspec = new X509EncodedKeySpec(data);
		return keyfactory.generatePublic(keyspec);
	}

	private static String generateBase64(PublicKey publicKey) {
		return BaseEncoding.base64().encode(publicKey.getEncoded());
	}
}
