package uc3m.jenarvaezg.dataprot2;

import java.security.PrivateKey;
import java.security.PublicKey;


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
			privKey = (PrivateKey) rsa.getKey(rsa.PRIVATE_KEY_FILE);//getPrivKey();			
			pubKey = (PublicKey) rsa.getKey(rsa.PUBLIC_KEY_FILE);//getPubKey();
		}catch(Exception e){
			System.out.println("Error getting keys");
			e.printStackTrace();
			System.exit(1);
		}
		
		byte[] plaintext = "Soy un texto ya yay yay".getBytes();	
		
		byte[] ciphertext = rsa.encrypt(plaintext, pubKey);
		
		
		byte[] deciphered = rsa.decrypt(ciphertext, privKey);
		
		System.out.println(new String(deciphered));
		
		byte[] signed = rsa.sign(plaintext, privKey);
		
		if(rsa.verify(plaintext, signed, pubKey)){
			System.out.println("Plaintext matches deciphered text");
		}else{
			System.out.println(":/");
		}
		
	}



}
