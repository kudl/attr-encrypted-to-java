package com.kudl.example;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static com.kudl.example.utils.AESCrypt.*;

@SpringBootTest
@RunWith(SpringRunner.class)
public class AESCryptTest {

	@Test
	public void ruby_arrt_encrypted_to_java_enc() throws Exception {
		final String key = "CksBkWat8R2r4y2EmiEABEm6ggVdfeqQ";
		final String rubyEncrypted = "TsnpRnlF700Fzr7PLGNohXmDOugBV0VnuBfF ";
		final String rubyIv = "MfyWT+DkNqqVi9Qu ";
		final String plainText = "01011112222";

		String iv = getRandomInitVector();
		System.out.println("IV : " + iv);

		String cipherText = encrypt(plainText, key, iv);
		System.out.println("Encrypted Text : " + cipherText);

		String decryptedText = decrypt(cipherText, key, iv);
		System.out.println("DeCrypted Text : " + decryptedText);

		String rubyDecryptedText = decrypt(rubyEncrypted, key, rubyIv);
		System.out.println("rubyDecryptedText Text : " + rubyDecryptedText);

		Assert.assertEquals(plainText, decryptedText);
		Assert.assertEquals(plainText, rubyDecryptedText);
	}
}
