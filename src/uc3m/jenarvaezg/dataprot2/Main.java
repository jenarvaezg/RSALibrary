package uc3m.jenarvaezg.dataprot2;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.xml.bind.DatatypeConverter;



/*
 * 
 * 100353494@pt1a614:~/workspace/dataprotection2$ echo "Prueba" | openssl rsautl -encrypt -pubin -inkey ./public.key > message.encrypted
	100353494@pt1a614:~/workspace/dataprotection2$ openssl rsautl -decrypt -inkey ./private.key < message.encrypted 
	Prueba

 */

public class Main {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		 
		RSALibrary rsa = new RSALibrary();
		
		rsa.generateKeys();
		PrivateKey privKey = null;
		PublicKey pubKey = null;
		
		try{
			privKey = getPrivKey();
			
			pubKey = getPubKey();
		}catch(Exception e){
			System.out.println("Error getting keys");
			e.printStackTrace();
			System.exit(1);
		}
		
		byte[] plaintext = "Soy un texto ya yay yay".getBytes();	
		
		byte[] ciphertext = rsa.encrypt(plaintext, pubKey);
		
		//System.out.println(Arrays.toString(ciphertext));
		
		byte[] deciphered = rsa.decrypt(ciphertext, privKey);
		
		System.out.println(new String(deciphered));
		
		byte[] signed = rsa.sign(plaintext, privKey);
		
		if(rsa.verify(plaintext, signed, pubKey)){
			System.out.println("YAY");
		}else{
			System.out.println("NAY");
		}
		
	}

	private static PrivateKey getPrivKey() throws Exception {
		
		BufferedReader reader = new BufferedReader(new FileReader(new File(RSALibrary.PRIVATE_KEY_FILE)));
		String header = reader.readLine();
		String base64encoded = reader.readLine().trim();
		String footer = reader.readLine().trim();
		
		
		if(!("-----BEGIN RSA PRIVATE KEY-----".equals(header) && "-----END RSA PRIVATE KEY-----".equals(footer))){
			throw new Exception("Private Key File not valid: ");
		}
		reader.close();		
		
		byte[] privateBytes = DatatypeConverter.parseBase64Binary(base64encoded);
		
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey key = keyFactory.generatePrivate(keySpec);		
		
	    return key;
	}

	private static PublicKey getPubKey() throws Exception {
		
		BufferedReader reader = new BufferedReader(new FileReader(new File(RSALibrary.PUBLIC_KEY_FILE)));
		String header = reader.readLine();
		String base64encoded = reader.readLine().trim();
		String footer = reader.readLine().trim();
		
		
		if(!("-----BEGIN RSA PUBLIC KEY-----".equals(header) && "-----END RSA PUBLIC KEY-----".equals(footer))){
			throw new Exception("Public Key File not valid: ");
		}
		reader.close();		
		
		byte[] publicBytes = DatatypeConverter.parseBase64Binary(base64encoded);
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey key = keyFactory.generatePublic(keySpec);
		
	    return key;
		
		
		
	}

}
