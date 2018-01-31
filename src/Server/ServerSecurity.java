package Server;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.Certificate;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import sun.security.pkcs10.PKCS10;
import org.bouncycastle.jce.PKCS10CertificationRequest;


public class ServerSecurity {
	
	DHParameterSpec dhParamFromServerPubKey;
	PublicKey clientPubKey;
	KeyAgreement serverKeyAgree;
	byte[] encodedParams;
	int ivSize=16;
	IvParameterSpec ivParams;
	byte[] iv;
	PublicKey pubKeyCC;

	//Initiates Diffie-Hellman key exchange protocol
	public byte[] initiateDH() throws Exception{
        
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(dhParamFromServerPubKey);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();
        
         serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());
        
        byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
		
        return serverPubKeyEnc;
	}
	
	//Function that accepts the key given by the client
	public void acceptKey(byte[] clientPubKeyEnc) throws Exception {
		KeyFactory serverKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPubKeyEnc);
        
        clientPubKey = serverKeyFac.generatePublic(x509KeySpec);
        dhParamFromServerPubKey = ((DHPublicKey)clientPubKey).getParams();
	}

	public SecretKeySpec serverDoPhase() throws Exception{
		serverKeyAgree.doPhase(clientPubKey, true);
		byte[] serverSharedSecret = serverKeyAgree.generateSecret();
		
		//Generate simmetric key
		SecretKeySpec serverAESKey = new SecretKeySpec(serverSharedSecret,0,16, "AES");
		
		return serverAESKey;
		
	}
	
	//Receives encoded message and decodes it returning the encrypt message 
	public byte[] decodeMessage (byte[] message) throws Exception {
		
		byte[] toSend = Base64.getDecoder().decode(message);
		
		return toSend;
	}
	
	public String decryptMessage (byte[] message, SecretKeySpec serverAESKey) throws Exception{
	
		//Extract Parameters
		iv= new byte[ivSize];
		System.arraycopy(message, 0, iv, 0, iv.length);
		ivParams = new IvParameterSpec(iv);
		
		int encryptedSize = message.length-ivSize;
		byte[] encrypted = new byte[encryptedSize];
		System.arraycopy(message, ivSize , encrypted, 0, encryptedSize);
		
		Cipher resultCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        resultCipher.init(Cipher.DECRYPT_MODE, serverAESKey, ivParams);
        byte[] recovered = resultCipher.doFinal(encrypted);
        String result = new String(recovered);
		
		return result;
	}
	
	// This function receives a plain message and returns a ciphered then encoded
	// one
	public byte[] encryptMessage(String message, SecretKeySpec serverAESKey) throws Exception {
		
		iv = new byte[ivSize];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		ivParams = new IvParameterSpec(iv);

		Cipher clientCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		clientCipher.init(Cipher.ENCRYPT_MODE, serverAESKey, ivParams);
		byte[] cipher = clientCipher.doFinal(message.getBytes());
		
		//Combine message with Parameters
				byte[] msg = new byte[cipher.length + ivSize ];
				System.arraycopy(iv, 0, msg, 0, ivSize);
				System.arraycopy(cipher, 0, msg, ivSize, cipher.length);

		return encodeJSON(msg);
	}

	// Encodes byte arrays (this is for JSON message exchanged)
	public byte[] encodeJSON(byte[] message) {
		byte[] jsonEncoded = Base64.getEncoder().encode(message);

		return jsonEncoded;

	}
	
	//Function used to verify if the client message belongs to the original owner
	public boolean verifyMessage(byte[] message) throws Exception {
		
		String cmdAsString = new String(message);
		JsonElement data =  new JsonParser().parse(cmdAsString);
		JsonElement ogMessage = data.getAsJsonObject().get("message");
		JsonElement signedMsg = data.getAsJsonObject().get("signed");
		JsonElement key = data.getAsJsonObject().get("key");
			
		
		Signature signAlg = Signature.getInstance("SHA1withRSA");
		KeyFactory keyGen = KeyFactory.getInstance("RSA");
		EncodedKeySpec publicKey= new X509EncodedKeySpec(Base64.getDecoder().decode(key.getAsString()));
		PublicKey pub = keyGen.generatePublic(publicKey);
		
		pubKeyCC = pub;
		
		signAlg.initVerify(pub);
		signAlg.update(ogMessage.getAsString().getBytes());
		
		return signAlg.verify(Base64.getDecoder().decode(signedMsg.getAsString()));
		
	}
	
	public String decodeMessage (String message) {
		
		String msgDecoded = new String(Base64.getDecoder().decode(message));
		
		return msgDecoded;
	}
	
	//Function used to retrieve the message to be decrypted
	public byte[] readMessage(byte[] message) throws Exception{
		String cmdAsString = new String(message);
		JsonElement data =  new JsonParser().parse(cmdAsString);
		JsonElement ogMessage = data.getAsJsonObject().get("message");	
		
		return decodeMessage(ogMessage.getAsString().getBytes());
	}
	
	public PublicKey decodeStoredKey (String keyEncoded) throws Exception {
		
		
		byte[] temp = Base64.getDecoder().decode(keyEncoded);
		KeyFactory keyGen = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKey= new X509EncodedKeySpec(temp);
		PublicKey pub = keyGen.generatePublic(publicKey);
		
		return pub;
	}

	
	public String generateUUIDHash(String BI) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("MD5");
		digest.digest(BI.getBytes());
		String uuid = new String(digest.digest());
		
		return uuid;
	}
	
	public byte[] encryptToStoreMsg(String msg, PublicKey pbKey)throws Exception{
		
		System.out.println("Mensagem: "+ msg);
		
		Cipher msgCipher = Cipher.getInstance("RSA");
		msgCipher.init(Cipher.ENCRYPT_MODE, pbKey);
		
		
		byte[] toStore = msgCipher.doFinal(Base64.getEncoder().encode(msg.getBytes()));
		
		return toStore;
	}
	
	public String getKey(byte[] obj) {
		String tmp = new String(obj);
		JsonElement parser = new JsonParser().parse(tmp);
		JsonElement key = parser.getAsJsonObject().get("pubKey");
		
		System.out.println("Chave no JSON: " + key.getAsString());
		
		
		return key.getAsString();
	}
	

}
