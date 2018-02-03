package Client;

import java.awt.EventQueue;
import java.io.BufferedReader;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.ConsoleHandler;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonStreamParser;
import com.google.gson.stream.JsonReader;

public class Client {
	
	static Socket socket;
	static PrintWriter out;
	static BufferedReader in;
	static JsonElement uuid;
	static DataOutputStream dOut;
	static DataInputStream dIn;
	static int user=ThreadLocalRandom.current().nextInt(0, 100000000 + 1);
	static PrivateKey pvKey;
	static PublicKey pubKey;
	static int counter=0;
	
	
	static ClientSecurity clientSec;
	
	static ccReader citizenCard;
	

	public static void main(String[] args) throws Exception {
		
		
		clientSec = new ClientSecurity();
		File currentDirectory = new File(new File("").getAbsolutePath());
		String f = currentDirectory.getAbsolutePath() + "/src/Client/CartaoCidadao.cfg";
		Provider p = new sun.security.pkcs11.SunPKCS11( f );
		Security.addProvider(p);
		loginMenu();
		createConn();
		initExchange();
		menu();
	}
	
	public static void createConn() throws Exception {
		
		try{  
			// Initiate DH Exchange
			socket = new Socket("localhost", 8080);
			dOut = new DataOutputStream(socket.getOutputStream());
			dIn = new DataInputStream(socket.getInputStream());
			byte[] toSend = clientSec.initiateDH();
			dOut.writeInt(toSend.length);
			dOut.write(toSend);

		     int length = dIn.readInt();                    // read length of incoming message
		     if(length>0) {
		         byte[] message = new byte[length];
		         dIn.readFully(message, 0, message.length); // read the message
		         clientSec.acceptKey(message);
		         clientSec.doPhase();
		     
		     }
		     
		   } catch (UnknownHostException e) {
		     System.out.println("Unknown host: localhost - Port 8080");
		     System.exit(1);
		   } catch  (IOException e) {
		     System.out.println("No I/O");
		     System.exit(1);
		   }
		
	}

	public static void initExchange() throws Exception{
		
		//Get private key for message signature
		KeyPair pair = clientSec.getKeys("AB");
		pvKey = pair.getPrivate();
		pubKey = pair.getPublic();
		
		System.out.println("Chave:"+ Base64.getEncoder().encodeToString(pubKey.getEncoded()));
		
		JsonObject init= new JsonObject();
		init.addProperty("type", "create");
		init.addProperty("uuid", "10"); 
		init.addProperty("pubKey", Base64.getEncoder().encodeToString(pubKey.getEncoded()));
		
		byte[] initSend = clientSec.encryptMessage(init.toString());
		byte[] signed = clientSec.signMessage(initSend, ccReader.getPrivateKey());
		sendCommand(initSend, signed, ccReader.getPublicKey());
	
		
		int length = dIn.readInt(); // read length of incoming message
		
		
		if (length > 0) {
			byte[] message = new byte[length];
			dIn.readFully(message, 0, message.length); // read the message

			if(clientSec.verifyMessage(message)) {
				String cmdAsString = new String(message);
				JsonElement tmp =  new JsonParser().parse(cmdAsString);
				JsonElement ogMessage = tmp.getAsJsonObject().get("message");
				byte[] getID = clientSec.decodeMessage(ogMessage.getAsString().getBytes());
				String userID = clientSec.decryptMessage(getID);
				JsonElement data = new JsonParser().parse(userID);
				uuid = data.getAsJsonObject().get("result");
			}else {
				System.out.println("Message not validated! Returning to Menu...");
				menu();
			}
			
			
		}
		
	}

	public static void closeConn() throws IOException {
		
		dIn.close();
		dOut.close();
		socket.close();
	}
	
	//This method puts everything in JSON format following the structure:
	//{	message:"",
	//	signed:"",
	//	key:""	}
	public static void sendCommand(byte[] command, byte[] signedCommand, PublicKey publicKey) throws Exception {
		
		JsonObject cmd = new JsonObject();
		cmd.addProperty("message", new String(command));
		cmd.addProperty("signed",Base64.getEncoder().encodeToString(signedCommand));
		cmd.addProperty("key", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		counter+=1;
		cmd.addProperty("tag", Integer.toString(counter));
		
		
		byte[] send =cmd.toString().getBytes("UTF-8");
		
		dOut.writeInt(send.length);
		dOut.write(send);
		dOut.flush();
	}
	
	//Method that reads the message received from the Server
	public static JsonElement readResult() throws Exception{
		
		JsonElement data = null;
		
		
			int length = dIn.readInt(); // read length of incoming message
			if (length > 0) {
				byte[] message = new byte[length];
				dIn.readFully(message, 0, message.length); // read the message
				if(clientSec.verifyMessage(message)) {
					String cmdAsString = new String(message);
					JsonElement tmp =  new JsonParser().parse(cmdAsString);
					JsonElement ogMessage = tmp.getAsJsonObject().get("message");
					JsonElement tag = tmp.getAsJsonObject().get("tag");
					if(tag.getAsInt() == counter+1) {
						byte[] getID = clientSec.decodeMessage(ogMessage.getAsString().getBytes());
						String userID = clientSec.decryptMessage(getID);
						System.out.println(userID);
						data = new JsonParser().parse(userID);
					}else {
						System.out.println("Tag:"+ tag.getAsInt());
						System.out.println("A message was lost! ");
						menu();
					}
						
					
				}else {
					System.out.println("Message not validated! Returning to Menu...");
					menu();
				}
				

			}
			return data;
	
	}
	
	//Method to send receipt - id is given by the CC
	public static void sendReceipt(String messageId, String message, PublicKey keyToUse) throws Exception {
		JsonObject receipt = new JsonObject();
		JsonObject receiptCredentials = new JsonObject();
		
		receiptCredentials.addProperty("message", message);
		receiptCredentials.addProperty("signed",Base64.getEncoder().encodeToString(clientSec.signMessage(message.getBytes(), ccReader.getPrivateKey())));
		receiptCredentials.addProperty("key",Base64.getEncoder().encodeToString(ccReader.getPublicKey().getEncoded()));
		
		receipt.addProperty("type", "receipt");
		receipt.addProperty("id", uuid.getAsString());
		receipt.addProperty("msg", messageId.toString());
		receipt.addProperty("receipt", receiptCredentials.toString());
		
		
		//byte[] sendReceipt = clientSec.encryptToDst(receipt.toString().getBytes(),keyToUse);
		byte[] toServerReceipt = clientSec.encryptMessage(receipt.toString());
		
		byte[] receiptSigned= clientSec.signMessage(toServerReceipt, pvKey);
		sendCommand(toServerReceipt, receiptSigned, pubKey);

		
		
	}

	
	public static void menu() throws Exception {
		
		System.out.println();
		System.out.println("User ID:" + uuid);
		
		readResults results = new readResults();
		
		
		//Creates new message every time the menu is opened
		JsonObject message = new JsonObject();
		
		Scanner scanner= new Scanner(System.in);
		
		System.out.println("\nSecure Messaging System: \n");
		System.out.println("1 - List Users");
		System.out.println("2 - Check New Messages");
		System.out.println("3 - List All Messages");
		System.out.println("4 - Send a New Message");
		System.out.println("5 - Receive Messages");
		System.out.println("6 - Check Status of Sent Messages");
		System.out.println("7 - LogOut");
		
		int op = scanner.nextInt();
		
		
		
		switch(op) {
		case 1:
			//LIST
			message.addProperty("type", "list");
			System.out.println("What user do you wish to find?");
			String wishID = scanner.nextLine();
			message.addProperty("id",wishID);
			if(wishID.equals(""))
				message.remove("id");
			byte[] sendList = clientSec.encryptMessage(message.toString());
			byte[] listSigned= clientSec.signMessage(sendList,  pvKey);
			System.out.println(pvKey.toString());
			sendCommand(sendList, listSigned, pubKey);
			results.readListResult(readResult().getAsJsonObject());
			break;
		case 2:
			//NEW
			message.addProperty("type", "new");
			message.addProperty("id",uuid.getAsString());
			byte[] sendNew = clientSec.encryptMessage(message.toString());
			byte[] newSigned= clientSec.signMessage(sendNew,  pvKey);
			sendCommand(sendNew, newSigned, pubKey);
			results.readNewMgs(readResult().getAsJsonObject());
			//System.out.println(readResult());
			break;
		case 3:
			//ALL
			message.addProperty("type", "all");
			message.addProperty("id",uuid.getAsString());
			byte[] sendAll = clientSec.encryptMessage(message.toString());
			byte[] allSigned= clientSec.signMessage(sendAll,  pvKey);
			sendCommand(sendAll, allSigned, pubKey);
			results.readAllMsg(readResult().getAsJsonObject());
			//System.out.println(readResult());
			break;
		case 4:
			//SEND
			//Message Creation
			
			System.out.println("Destination ID?");
			int dst = scanner.nextInt();
			//Send list to get the pubKey for message encryption
			message.addProperty("type", "list");
			message.addProperty("id",dst);
			byte[] sendReq = clientSec.encryptMessage(message.toString());
			byte[] reqSigned= clientSec.signMessage(sendReq,  pvKey);
			sendCommand(sendReq, reqSigned, pubKey);
			JsonElement dstPubKey=readResult().getAsJsonObject().get("data").getAsJsonArray().get(0).getAsJsonObject().get("sec-data");
			PublicKey keyToUse = clientSec.getDstKey(dstPubKey);
			//
			message = new JsonObject();
			message.addProperty("type", "send");
			message.addProperty("src",uuid.getAsString());
			message.addProperty("dst", dst);
			scanner.nextLine();
			System.out.println("Write your message: \n");
			String msg = scanner.nextLine();
			//Message itself is encoded to Base64
			String m = Base64.getEncoder().encodeToString(clientSec.encryptToDst(msg.getBytes(), keyToUse));
			message.addProperty("msg", m);
			message.addProperty("copy", m);
			//Encrypt and then encode to BASE 64 message to Send to Server (AES)
			byte[] toSend = clientSec.encryptMessage(message.toString());
			byte[] toSendSigned= clientSec.signMessage(toSend,  ccReader.getPrivateKey());
			sendCommand(toSend, toSendSigned, ccReader.getPublicKey());
			
			//Reads the JSON received by Server
			System.out.println(readResult());
			
			break;
		case 5:
			//RECV
				message.addProperty("type", "recv");
				message.addProperty("id",uuid.getAsString() );
				scanner.nextLine();
				System.out.println("What message would you like to read?");
				String targetMsg = scanner.nextLine();
				message.addProperty("msg", targetMsg);
				scanner.nextLine();
				byte[] sendRecv = clientSec.encryptMessage(message.toString());	
				byte[] recvSigned= clientSec.signMessage(sendRecv,  pvKey);
				sendCommand(sendRecv, recvSigned,pubKey);
				JsonObject obj = readResult().getAsJsonObject();	
				
				if(results.readMessage(obj)) {
					message.addProperty("type", "list");
					message.addProperty("id",obj.get("result").getAsJsonArray().get(0).getAsString());
					byte[] sendRec = clientSec.encryptMessage(message.toString());
					byte[] recSigned= clientSec.signMessage(sendRec,  pvKey);
					sendCommand(sendRec, recSigned, pubKey);
					JsonElement dstRecPubKey=readResult().getAsJsonObject().get("data").getAsJsonArray().get(0).getAsJsonObject().get("sec-data");
					PublicKey keyToUseRec = clientSec.getDstKey(dstRecPubKey);
					byte[] messageEncoded = Base64.getDecoder().decode(obj.get("result").getAsJsonArray().get(1).getAsString().getBytes());
					String mensagem=new String(clientSec.decryptStoredMsg(messageEncoded, pvKey));
					System.out.println("Mensagem: "+ mensagem);
					
					System.out.println("Sending receipt...");
					sendReceipt(targetMsg,mensagem, keyToUseRec);
				}else {
					menu();
				}
			
				
			break;
		case 6:
			//STATUS
			message.addProperty("type", "status");
			message.addProperty("id", uuid.getAsString());
			scanner.nextLine();
			System.out.println("Message?");
			String msge = scanner.nextLine();
			message.addProperty("msg", msge);
			byte[] sendStatus = clientSec.encryptMessage(message.toString());
			byte[] statusSigned= clientSec.signMessage(sendStatus,  pvKey);
			sendCommand(sendStatus, statusSigned, pubKey);
			System.out.println();
			if(results.readReceipts(readResult().getAsJsonObject(), clientSec)) {
				break;
			}else
				menu();			
		case 7:
			closeConn();
		}
		menu();
		
	}
	
	public static void loginMenu() throws Exception{
		
		String BI="";
		
		System.out.println("|| Secure Messaging Client || ");
		System.out.println("To login please insert your Citizen Card. ");
		synchronized (Thread.currentThread()) {
			while((BI=ccReader.getBI()) == null){
				System.out.println("Citizen Card not inserted.");
				Thread.currentThread().wait(5000);
			}
			
		
		}	
		
		
			
	}
	
	
}
