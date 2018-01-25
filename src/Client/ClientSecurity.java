package Client;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.text.IconView;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class ClientSecurity{ 

	KeyAgreement clientAgree;
	PublicKey serverPubKey;
	SecretKeySpec clientAESKey;
	IvParameterSpec iv;
	//private static final String alphabet= "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	Cipher clientCipher;
	ccReader reader;
	 byte[] digest;
	 PublicKey pub;
	
	//Initiates DH Agreement
	public byte[] initiateDH() throws Exception {
		
		KeyPairGenerator clientKeyPairGen = KeyPairGenerator.getInstance("DH");
		clientKeyPairGen.initialize(2048);
		KeyPair clientKeyPair = clientKeyPairGen.generateKeyPair();
		
		clientAgree = KeyAgreement.getInstance("DH");
		clientAgree.init(clientKeyPair.getPrivate());
		
		//Encode public key and send it
		byte[] clientPubKey = clientKeyPair.getPublic().getEncoded();
		
		return clientPubKey;
	}
	
	//Accepts server key
	public void acceptKey(byte[] serverPubKeyEnc) throws Exception{
		
		KeyFactory clientKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPubKeyEnc);
        serverPubKey = clientKeyFac.generatePublic(x509KeySpec);
       
	}
	
	//Generates shared secret
	public void doPhase() throws Exception{
		
		clientAgree.doPhase(serverPubKey, true);
        
        byte[] clientSharedSecret = clientAgree.generateSecret();
        
        //Generate simmetric Key
        clientAESKey = new SecretKeySpec(clientSharedSecret,0,16, "AES");
        
	}
	
	//This function receives a plain message and returns a ciphered then encoded one
	public byte[] encryptMessage (String message) throws Exception{
		
		clientCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		clientCipher.init(Cipher.ENCRYPT_MODE, clientAESKey);
		byte[] cipher = clientCipher.doFinal(message.getBytes());
		
		return encodeJSON(cipher);
	}
	
	//Receives bytes decoded and then decrypts the message inside
	public String decryptMessage(byte[] message) throws Exception {

		Cipher resultCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		resultCipher.init(Cipher.DECRYPT_MODE, clientAESKey);
		byte[] recovered = resultCipher.doFinal(message);
		String result = new String(recovered);

		return result;
	}
	
	//Messages are only decoded when they arrive at the destination
	public String decodeMessage(JsonObject message) throws Exception{
		
		JsonArray m = message.get("result").getAsJsonArray();
		String msg = m.get(1).getAsString();
		byte[] toSend = Base64.getDecoder().decode(msg.getBytes());
		String toSend2= new String(toSend);
		
		return toSend2;
		
	}
	
	//Encodes plain text messages
	public String encodeMessage(String message) {
		
		String msgEncoded = Base64.getEncoder().encodeToString(message.getBytes());
		
		return msgEncoded;
	}
	
	
	//Encodes byte arrays (this is for JSON message exchanged)
	public byte[] encodeJSON (byte[] message) {
		
		byte[] jsonEncoded = Base64.getEncoder().encode(message);
		
		return jsonEncoded;
		
	}
	
	//Decodes message received
	public byte[] decodeMessage(byte[] message) throws Exception {

		byte[] toSend = Base64.getDecoder().decode(message);

		return toSend;
	}
	
	public KeyPair getKeys() throws Exception {
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		
		return pair;
	}
	
	//Function to sign Message
	public byte[] signMessage(byte[] message, PrivateKey key) throws Exception {
		
		Signature signAlg = Signature.getInstance("SHA1withRSA");
		signAlg.initSign(key);
		signAlg.update(message);
		byte[] signedMessage = signAlg.sign();
		
		
		return signedMessage;
	}
	
}
