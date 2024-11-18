package pt.tecnico.crypto;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Test;

public class SymCryptoTest {
	/** Plain text to cipher. */
	private final String plainText = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";//"This is the plain text!";
	/** Plain text bytes. */
	private final byte[] plainBytes = plainText.getBytes();

	/** Symmetric cryptography algorithm. */
	private static final String SYM_ALGO = "AES";
	/** Symmetric algorithm key size. */
	private static final int SYM_KEY_SIZE = 128;
	/**
	 * Symmetric cipher: combination of algorithm, block processing, and padding.
	 */
	private static final String SYM_CIPHER = "AES/CBC/PKCS5Padding"; //"AES/ECB/PKCS5Padding";

	/**
	 * Secret key cryptography test.
	 * 
	 * @throws Exception because test is not concerned with exception handling
	 */
	@Test
	public void testSymCrypto() throws Exception {
		//Generate a random Initialization Vector (IV) for each encryption session
		System.out.println("Generating IV...");
		SecureRandom secureRandom = SecureRandom.getInstanceStrong();
		byte[] ivBytes = new byte[Cipher.getInstance(SYM_CIPHER).getBlockSize()];
		secureRandom.nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		System.out.print("IV (in hexadecimal): ");
		System.out.println(printHexBinary(iv.getIV()));

		System.out.print("TEST '");
		System.out.print(SYM_CIPHER);
		System.out.println("'");

		System.out.println("Text:");
		System.out.println(plainText);
		System.out.println("Bytes:");
		System.out.println(printHexBinary(plainBytes));

		// get a AES private key
		System.out.println("Generating AES key...");
		KeyGenerator keyGen = KeyGenerator.getInstance(SYM_ALGO);
		keyGen.init(SYM_KEY_SIZE);
		Key key = keyGen.generateKey();
		System.out.print("Key: ");
		System.out.println(printHexBinary(key.getEncoded()));

		// get a AES cipher object and print the provider
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);
		System.out.println(cipher.getProvider().getInfo());

		// encrypt using the key and the plain text
		System.out.println("Ciphering...");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] cipherBytes = cipher.doFinal(plainBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(cipherBytes));

		// decipher the cipher text using the same key
		System.out.println("Deciphering...");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		byte[] newPlainBytes = cipher.doFinal(cipherBytes);
		System.out.print("Result: ");
		System.out.println(printHexBinary(newPlainBytes));

		System.out.println("Text:");
		String newPlainText = new String(newPlainBytes);
		System.out.println(newPlainText);

		assertEquals(plainText, newPlainText);

		System.out.println();
		System.out.println();
	}
}
