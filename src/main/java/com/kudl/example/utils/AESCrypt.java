package com.kudl.example.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Slf4j
public class AESCrypt {

	public static final int GCM_IV_LENGTH = 12;
	public static final int GCM_TAG_LENGTH = 16;

	private static final String CHARSET_NAME = "UTF-8";
	private static final String TRANSFORMATION = "AES/GCM/NoPadding";
	private static final String ALGORITHM = "AES";
	private static final String SPACE = "";
	private static final String NEW_LINE = "\\n";

	public static String encrypt(String plaintext, String key, String IV) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(CHARSET_NAME), ALGORITHM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.decodeBase64(IV));

		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
		byte[] cipherText = cipher.doFinal(plaintext.getBytes());

		return Base64.encodeBase64String(cipherText);
	}

	public static String decrypt(String cipherText, String key, String IV) throws Exception {
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);

		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(CHARSET_NAME), ALGORITHM);
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.decodeBase64(IV.replace(NEW_LINE, SPACE)));

		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
		byte[] decryptedText = cipher.doFinal(Base64.decodeBase64(cipherText.replace(NEW_LINE, SPACE)));

		return new String(decryptedText);
	}

	public static String getRandomInitVector() throws NoSuchAlgorithmException {
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		byte[] iv = new byte[GCM_IV_LENGTH];
		rand.nextBytes(iv);
		return Base64.encodeBase64String(iv);
	}
}
