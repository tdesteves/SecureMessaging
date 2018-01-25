package Client;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class readResults {
	
	ClientSecurity clientSec;
	
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
			System.out.println("No permissions or badly formatted JSON!");
			return false;
		}
	
		return true;
		
	}

}
