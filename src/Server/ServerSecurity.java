package Server;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServerSecurity {
	
	DHParameterSpec dhParamFromServerPubKey;
	PublicKey clientPubKey;
	KeyAgreement serverKeyAgree;
	byte[] encodedParams;
	


	public byte[] initiateDH() throws Exception{
        
        KeyPairGenerator serverKpairGen = KeyPairGenerator.getInstance("DH");
        serverKpairGen.initialize(dhParamFromServerPubKey);
        KeyPair serverKpair = serverKpairGen.generateKeyPair();
        
         serverKeyAgree = KeyAgreement.getInstance("DH");
        serverKeyAgree.init(serverKpair.getPrivate());
        
        byte[] serverPubKeyEnc = serverKpair.getPublic().getEncoded();
		
        return serverPubKeyEnc;
	}
	
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
	
		Cipher resultCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        resultCipher.init(Cipher.DECRYPT_MODE, serverAESKey);
        byte[] recovered = resultCipher.doFinal(message);
        String result = new String(recovered);
		
		return result;
	}
	
	// This function receives a plain message and returns a ciphered then encoded
	// one
	public byte[] encryptMessage(String message, SecretKeySpec serverAESKey) throws Exception {

		Cipher clientCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		clientCipher.init(Cipher.ENCRYPT_MODE, serverAESKey);
		byte[] cipher = clientCipher.doFinal(message.getBytes());

		return encodeJSON(cipher);
	}

	// Encodes byte arrays (this is for JSON message exchanged)
	public byte[] encodeJSON(byte[] message) {
		byte[] jsonEncoded = Base64.getEncoder().encode(message);

		return jsonEncoded;

	}
}
