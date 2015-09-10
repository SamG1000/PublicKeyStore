package com.github.publickey;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * {@link PublicKeyArchive} using {@link ZipFile} implementation.
 * 
 * All keys are stored inside a zip file, with compressed filenames being key
 * aliases. Optionally {@link ZipEntry#getComment()} will keep the algorithm of
 * the key.
 * 
 * @author Simon Galperin
 */
public class PublicKeyZipArchive implements PublicKeyArchive {
	private final File file;
	
	/**
	 * @param filename
	 */
	public PublicKeyZipArchive(String filename) {
		if (!isValid(filename)) {
			throw new IllegalArgumentException("Filename is missing or invalid");
		}
		
		this.file = new File(filename);
		
	}

	@Override
	public void update(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		FileInputStream stream = new FileInputStream(file);
		try {
			// input file
			ZipInputStream in = new ZipInputStream(stream);
			try {
				boolean changed = keyStore.isChanged();
				// mark the store unchanged, so we can track if it
				keyStore.setChanged(false);
				
				Reader reader = new InputStreamReader(in);

				ZipEntry entry = in.getNextEntry();
				while (entry != null) {
					String alias = entry.getName();
					
					String algorithm;
					
					// assume that extra bytes store the algorithm
					byte[] algorithmBytes = entry.getExtra();
					if (algorithmBytes != null) {
						algorithm = new String(algorithmBytes);
					} else {
						algorithm = "RSA";
					}
					PublicKey publicKey = PublicKeyPemUtility.readKey(reader, algorithm);
					keyStore.add(alias, publicKey);
					entry = in.getNextEntry();
				}
				
				keyStore.setChanged(changed);
			} finally {
				in.close();
			}
		} finally {
			stream.close();
		}
	}
	
	/* (non-Javadoc)
	 * @see com.comcast.x1.sat.PublicKeyArchive#load(com.comcast.x1.sat.PublicKeyStore)
	 */
	public void load(PublicKeyStore keyStore) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		keyStore.clear();
		
		update(keyStore);
	}

	/* (non-Javadoc)
	 * @see com.comcast.x1.sat.PublicKeyArchive#store(com.comcast.x1.sat.PublicKeyStore)
	 */
	public void store(PublicKeyStore keyStore) throws IOException {
		FileOutputStream stream = new FileOutputStream(file);
		try {
			// out put file
			ZipOutputStream out = new ZipOutputStream(stream);
			try {

				Writer writer = new OutputStreamWriter(out);
				for (Entry<String, PublicKey> keyEntry : keyStore) {
					String alias = keyEntry.getKey();
					PublicKey publicKey = keyEntry.getValue();
					String algorithm = publicKey.getAlgorithm();
					
					ZipEntry entry = new ZipEntry(alias);
					entry.setExtra(algorithm.getBytes());
					
					out.putNextEntry(entry);
					
					
					PublicKeyPemUtility.writeKey(writer, publicKey);
					writer.flush();
				}
				
				keyStore.setChanged(false);
			} finally {
				out.close();
			}
		} finally {
			stream.close();
		}
	}

	private static boolean isValid(String filename) {
		try {
			Paths.get(filename);
			return true;
		} catch (InvalidPathException e) {
			return false;
		}
	}	
}
