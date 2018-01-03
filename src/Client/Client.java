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
		
		JsonObject init= new JsonObject();
		init.addProperty("type", "create");
		init.addProperty("uuid", user);
		
		byte[] initSend = clientSec.encryptMessage(init.toString());
		byte[] signed = clientSec.signMessage(initSend, ccReader.getPrivateKey());
		sendCommand(initSend, signed, clientSec.pub);
	
	
		int length = dIn.readInt(); // read length of incoming message
		if (length > 0) {
			byte[] message = new byte[length];
			dIn.readFully(message, 0, message.length); // read the message		
			byte[] getID = clientSec.decodeMessage(message);
			String userID = clientSec.decryptMessage(getID);
			JsonElement data = new JsonParser().parse(userID);
			uuid = data.getAsJsonObject().get("result");
			
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
		
		System.out.println("Mensagem em JSON: " + cmd.toString());
		
		byte[] send =cmd.toString().getBytes("UTF-8");
		
		dOut.writeInt(send.length);
		dOut.write(send);
		dOut.flush();
	}
	
	//Method that reads the message received from the Server
	public static String readResult() throws Exception{
		
		JsonElement data = null;
		
		
			int length = dIn.readInt(); // read length of incoming message
			if (length > 0) {
				byte[] message = new byte[length];
				dIn.readFully(message, 0, message.length); // read the message
				byte[] getID = clientSec.decodeMessage(message);
				String userID = clientSec.decryptMessage(getID);
				data = new JsonParser().parse(userID);

			}
			return data.toString();
	
	}
	
	//Method to send receipt - id is given by the CC
	public static void sendReceipt(String message) throws Exception {
		JsonObject receipt = new JsonObject();
		
		receipt.addProperty("type", "receipt");
		receipt.addProperty("id", uuid.getAsString());
		receipt.addProperty("msg", message);
		receipt.addProperty("receipt", "Vista.");
		
		byte[] sendRecv = clientSec.encryptMessage(receipt.toString());
		dOut.writeInt(sendRecv.length);
		dOut.write(sendRecv);
		dOut.flush();
	}

	
	public static void menu() throws Exception {
		
		System.out.println("User ID:" + uuid);
		
		
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
		
		int op = scanner.nextInt();
		
		switch(op) {
		case 1:
			//LIST
			message.addProperty("type", "list");
			//message.addProperty("id",uuid.getAsString());
			byte[] sendList = clientSec.encryptMessage(message.toString());
			byte[] listSigned= clientSec.signMessage(sendList,  ccReader.getPrivateKey());
			sendCommand(sendList, listSigned, clientSec.pub);
			System.out.println(readResult());
			break;
		case 2:
			//NEW
			message.addProperty("type", "new");
			message.addProperty("id",uuid.getAsString());
			byte[] sendNew = clientSec.encryptMessage(message.toString());
			byte[] newSigned= clientSec.signMessage(sendNew,  ccReader.getPrivateKey());
			sendCommand(sendNew, newSigned, clientSec.pub);
			System.out.println(readResult());
			break;
		case 3:
			//ALL
			message.addProperty("type", "all");
			message.addProperty("id",uuid.getAsString());
			byte[] sendAll = clientSec.encryptMessage(message.toString());
			byte[] allSigned= clientSec.signMessage(sendAll,  ccReader.getPrivateKey());
			sendCommand(sendAll, allSigned, clientSec.pub);
			System.out.println(readResult());
			break;
		case 4:
			//SEND
			//Message Creation
			message.addProperty("type", "send");
			message.addProperty("src",uuid.getAsString());
			System.out.println("Destination ID?");
			int dst = scanner.nextInt();
			message.addProperty("dst", dst);
			scanner.nextLine();
			System.out.println("Write your message: \n");
			String msg = scanner.nextLine();
			
			//Message itself is encoded to Base64
			message.addProperty("msg", clientSec.encodeMessage(msg));
			message.addProperty("copy", clientSec.encodeMessage(msg));
			//Encrypt and then encode to BASE 64 message to Send to Server (AES)
			byte[] toSend = clientSec.encryptMessage(message.toString());
			byte[] toSendSigned= clientSec.signMessage(toSend,  ccReader.getPrivateKey());
			sendCommand(toSend, toSendSigned, clientSec.pub);
			
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
			byte[] recvSigned= clientSec.signMessage(sendRecv,  ccReader.getPrivateKey());
			sendCommand(sendRecv, recvSigned, clientSec.pub);
			System.out.println("Sending receipt...");
			sendReceipt(targetMsg);
			JsonObject obj = new JsonParser().parse(readResult()).getAsJsonObject();
			System.out.println("Mensagem: "+ clientSec.decodeMessage(obj));
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
			byte[] statusSigned= clientSec.signMessage(sendStatus,  ccReader.getPrivateKey());
			sendCommand(sendStatus, statusSigned, clientSec.pub);
			System.out.println(readResult());			
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
