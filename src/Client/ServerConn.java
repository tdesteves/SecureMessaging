package Client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import com.google.gson.JsonObject;

public class ServerConn {

	Socket socket;
	
	ServerConn(Socket socket) throws IOException{
		this.socket=socket;
	
		
	}
	
	public void connClose(Socket socket) throws IOException {
		
		try {
			socket.getInputStream().close();
			socket.getOutputStream().close();
			socket.close();
		} catch (IOException e) {
			System.err.println("Error in: " + this.getClass().getName() + " line " + 
					Thread.currentThread().getStackTrace()[1].getLineNumber() + "\nError: " + e);
		}
	}
	
	public void sendJson() throws IOException {
		
		JsonObject messageTest= new JsonObject();
		messageTest.addProperty("type", "create");
		messageTest.addProperty("uuid", 1);
		
		
	
		System.out.println("Mensagem Enviada!");		
		
		
	}
}
