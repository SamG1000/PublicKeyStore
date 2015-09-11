# PublicKeyStore
Light keystore implementation for managing and storing only PublicKeys in Java

Maven:
```xml
<dependency>
  <groupId>org.java.security</groupId>
  <artifactId>public-key-store</artifactId>
  <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Note: Library depends on:
  Java 1.6

## Components:

This library provides three components:
- PublicKeyStore (for storing PublicKeys and it's aliases)
- PublicKeyArchive (for storing PublicKeytStore)
-- The library comes with PublicKeyZipArchive that is able to store PublicKeyStore as a zip file of PEM encoded Public Keys
- PublicKeyPemUtility (for reading/writing PEM encoded public keys)

## Usage:

Here's an example of the token creation from scratch:
```java
	KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	KeyPair keyPair = generator.generateKeyPair();
	PublicKey key = keyPair.getPublic();
	...
	PublicKeyStore keyStore = new PublicKeyStore();
	keyStore.add("alias", key);
	...
	File file = File.createTempFile(getClass().getSimpleName() + "-", ".pubar");
	file.deleteOnExit();

	PublicKeyZipArchive archive = new PublicKeyZipArchive(file.getAbsolutePath());
	archive.store(keyStore);
```

The Maven artifacts are deployed with the root hmaven2 repository at:
http://repo1.maven.org/maven2/com/github/publickey/public-key-store/

Sample repository configuration
```xml
<repository>
	<id>central</id>
	<name>Maven Repository Switchboard</name>
	<layout>default</layout>
	<url>http://repo1.maven.org/maven2/</url>
	<snapshots>
		<enabled>false</enabled>
	</snapshots>
</repository>
```

The Maven artifacts are also avaialble through with Sonatype at:
https://oss.sonatype.org/service/local/repositories/releases/content/
