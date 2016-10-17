package uc3m.jenarvaezg.dataprot2;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;


public class RSALibrary {

  // String to hold name of the encryption algorithm.
  public final String ALGORITHM = "RSA";

  //String to hold the name of the private key file.
  public final String PRIVATE_KEY_FILE = "./private.key";

  // String to hold name of the public key file.
  public final String PUBLIC_KEY_FILE = "./public.key";
  
  
  
  public Key getKey(String path) throws Exception{
	  Key key = null;
	  Boolean isPublic = false;
	  String base64encoded = "";
	  String line;
	  
	  BufferedReader reader = new BufferedReader(new FileReader(new File(path)));
	  String header = reader.readLine();
	  
	  if("-----BEGIN PUBLIC KEY-----".equals(header)){
		  isPublic = true;
	  }else if(!"-----BEGIN RSA PRIVATE KEY-----".equals(header)){
		  reader.close();
		  throw new Exception("Key file header wrong: " + path + " got: " + header);
	  }
	  
	  try{
		  for(line = reader.readLine();; line = reader.readLine()){
			  
			  base64encoded += line;
			  if(line.length() != 64){
				 line = reader.readLine();
				 break;
			  }
		  }
	  }catch(IOException e){
		  e.printStackTrace();
		  throw new Exception("Key file missing footer");
	  }finally{
		  reader.close();
	  }
	  if((isPublic && !"-----END PUBLIC KEY-----".equals(line)) || (!isPublic && !"-----END RSA PRIVATE KEY-----".equals(line))){
		  throw new Exception("Key file has wrong footer: " + path);
	  }
	  
	  
	  byte[] keyBytes = DatatypeConverter.parseBase64Binary(base64encoded);
	
	  if(isPublic){
		  X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		  key = keyFactory.generatePublic(keySpec);
	  }else{
		  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		  KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		  key = keyFactory.generatePrivate(keySpec);
	  } 
	  
	  
	  return key;
  }
  
  private void saveKey(Key key, String path) throws IOException{
	  byte[] encoded = key.getEncoded();
	  String base64encoded = new String(DatatypeConverter.printBase64Binary(encoded));
	  String keyString = new String();
	  
	  int i;
	  for(i = 0; i  < base64encoded.length() / 64 ; i++){
		  keyString += base64encoded.substring(i*64, i*64+64) + "\n";
	  }
	  keyString += base64encoded.substring(i*64) + "\n";
	  
	  if(key instanceof PrivateKey){
		  
		  keyString = "-----BEGIN RSA PRIVATE KEY-----\n" + keyString +"-----END RSA PRIVATE KEY-----\n";
		  
	  }else{
		  keyString = "-----BEGIN PUBLIC KEY-----\n" + keyString + "-----END PUBLIC KEY-----\n";
	  }
	  
	  DataOutputStream o = new DataOutputStream(new FileOutputStream(path));
	  o.write(keyString.getBytes());
	  o.flush();
	  o.close();
  }
  
  

  /***********************************************************************************/
   /* Generates an RSA key pair (a public and a private key) of 1024 bits length */
   /* Stores the keys in the files defined by PUBLIC_KEY_FILE and PRIVATE_KEY_FILE */
   /* Throws IOException */
  /***********************************************************************************/
  public void generateKeys() throws IOException {

    try {

      final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      keyGen.initialize(1024);
      KeyPair keyPair = keyGen.genKeyPair();
      
      
   // Use KeyGen to generate a public and a private key
      PrivateKey privKey = keyPair.getPrivate();
      PublicKey pubKey = keyPair.getPublic();
      
      saveKey(pubKey, PUBLIC_KEY_FILE);
      saveKey(privKey, PRIVATE_KEY_FILE);
      
  	} catch (NoSuchAlgorithmException e) {
		System.out.println("Exception: " + e.getMessage());
		System.exit(-1);
	}
  }


  /***********************************************************************************/
  /* Encrypts a plaintext using an RSA public key. */
  /* Arguments: the plaintext and the RSA public key */
  /* Returns a byte array with the ciphertext */
  /***********************************************************************************/
  public byte[] encrypt(byte[] plaintext, PublicKey key) {

    byte[] ciphertext = null;

    try {

      // Gets an RSA cipher object
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      //initialize the cipher object and use it to encrypt the plaintext
      cipher.init(Cipher.ENCRYPT_MODE, key);
      
     
      cipher.update(plaintext); 
      ciphertext = cipher.doFinal();


    } catch (Exception e) {
      e.printStackTrace();
    }
    return ciphertext;
  }


  /***********************************************************************************/
  /* Decrypts a ciphertext using an RSA private key. */
  /* Arguments: the ciphertext and the RSA private key */
  /* Returns a byte array with the plaintext */
  /***********************************************************************************/
  public byte[] decrypt(byte[] ciphertext, PrivateKey key) {

    byte[] plaintext = null;

    try {
      // Gets an RSA cipher object
      final Cipher cipher = Cipher.getInstance(ALGORITHM);
      // initialize the cipher object and use it to decrypt the ciphertext
      cipher.init(Cipher.DECRYPT_MODE, key);
      plaintext = cipher.doFinal(ciphertext);

    } catch (Exception ex) {
      ex.printStackTrace();
    }

    return plaintext;
  }

  /***********************************************************************************/
  /* Signs a plaintext using an RSA private key. */
  /* Arguments: the plaintext and the RSA private key */
  /* Returns a byte array with the signature */
  /***********************************************************************************/
  public byte[] sign(byte[] plaintext, PrivateKey key) {
		
    byte[] signedInfo = null;

    try {

	  // Gets a Signature object
      Signature signature = Signature.getInstance("SHA1withRSA");

	  // initialize the signature oject with the private key
	  
      signature.initSign(key);      
	
	  // set plaintext as the bytes to be signed
      
      signature.update(plaintext);
	
	  // sign the plaintext and obtain the signature (signedInfo)
      
      signedInfo = signature.sign();


    } catch (Exception ex) {
      ex.printStackTrace();
    }

	return signedInfo;
  }
	
  /***********************************************************************************/
  /* Verifies a signature over a plaintext */
  /* Arguments: the plaintext, the signature to be verified (signed) 
  /* and the RSA public key */
  /* Returns TRUE if the signature was verified, false if not */
  /***********************************************************************************/
  public boolean verify(byte[] plaintext, byte[] signed, PublicKey key) {

	boolean result = false;

    try {

 	 // Gets a Signature object
     Signature signature = Signature.getInstance("SHA1withRSA");

	  // initialize the signature oject with the public key
     signature.initVerify(key);


	  // set plaintext as the bytes to be veryfied
     signature.update(plaintext);


	  //verify the signature (signed). Store the outcome in the boolean result
	  
     result = signature.verify(signed);
     
	
    } catch (Exception ex) {
      ex.printStackTrace();
    }

	return result;
  }
	
}

