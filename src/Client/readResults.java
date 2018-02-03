package Client;

import java.security.PrivateKey;
import java.util.Base64;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class readResults {
	

	
	public void readListResult(JsonObject data) {
		
		System.out.println("Available Users:");
	
		JsonArray array = data.getAsJsonArray("data");
		for(int i = 0; i< array.size();i++) {
			 System.out.println( array.get(i).getAsJsonObject().get("id").getAsString());
			
		}
		
	}
	
	public void readNewMgs(JsonObject data) {
		
		System.out.println("New Messages: ");
		JsonArray array = data.getAsJsonArray("result");
		if(array.size()==0)
			System.out.println("There are no new messages!");
		else {
			for(int i = 0; i< array.size();i++) {
				 System.out.println( array.get(i).getAsString());
				
			}
		}
	}
	
	public void readAllMsg(JsonObject data) {

		System.out.println("All Messages: ");
		JsonArray array = data.getAsJsonArray("result");
		if(array.size()==0)
			System.out.println("There are no messages!");
		else {
			System.out.println("Message box:");
			for(int i = 0; i< array.get(0).getAsJsonArray().size();i++) {
				 System.out.println( array.get(0).getAsJsonArray().get(i).getAsString());	
			}
			System.out.println("Sent Messages Box: ");
			for(int i = 0; i< array.get(1).getAsJsonArray().size();i++) {
				 System.out.println( array.get(1).getAsJsonArray().get(i).getAsString());	
			}
		}
	}
	
	public boolean readMessage(JsonObject obj) throws Exception{
		
		if(obj.get("error")!=null) {
			if(obj.get("error").getAsString().equals("wrong parameters")) {
				System.out.println("There's no message on your mbox with that name!");
				return false;
			}
		}
			return true;
		
	}
	
	public boolean readReceipts(JsonObject receipt, ClientSecurity clientSec, PrivateKey pvKey) throws Exception{
		
		JsonObject array = receipt.getAsJsonObject("result");
		
		String ogMessage = array.get("msg").getAsString();
		
		System.out.println("Mensagem original: " + ogMessage);
		
		JsonArray rcpt = array.getAsJsonArray("receipts");
		if(rcpt.size()==0) {
			System.out.println("Yet not read!");
			return false;
		}else {
			JsonElement og= array.get("msg");
			JsonArray rcps = array.get("receipts").getAsJsonArray();
			JsonObject rcp = rcps.get(0).getAsJsonObject();
			
			byte[] msg = Base64.getDecoder().decode(og.getAsString().getBytes());
			
			JsonObject tmp = rcpt.get(0).getAsJsonObject();
			
			System.out.println("Date: "+ tmp.get("date"));
			System.out.println("Id: "+ tmp.get("id"));
			System.out.println("Signed: "+ clientSec.verifyReceipt(rcp.get("receipt").toString().getBytes(), ogMessage));
			return true;
		}
			
		
	}
	
	public JsonObject getReceipt(JsonObject obj) {
	
		JsonObject result = obj.get("result").getAsJsonObject();
		JsonObject message = result.get("message").getAsJsonObject();
		JsonArray receipts = result.get("receipts").getAsJsonArray();
		
		return receipts.get(0).getAsJsonObject();
	}

}
