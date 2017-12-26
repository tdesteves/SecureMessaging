package Server;

import java.net.Socket;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;

import javax.activation.DataSource;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import com.mysql.jdbc.Connection;
import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;

import java.net.ServerSocket;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;

class Server {
	
	static ServerSecurity sec;
	static DataOutputStream dOut;
	static DataInputStream dIn;
	static SecretKeySpec serverAESKey;

    static public void
    waitForClients ( ServerSocket s ) {
        ServerControl registry = new ServerControl();

        try {
            while (true) {
                Socket c = s.accept();
                sec= new ServerSecurity();
                dIn = new DataInputStream(c.getInputStream());
        			dOut = new DataOutputStream(c.getOutputStream());
                ServerActions handler = new ServerActions( c, registry, sec );
                new Thread( handler ).start ();
            }
        } catch ( Exception e ) {
            System.err.print( "Cannot use socket: " + e );
        }

    }
    

    public static void main ( String[] args ) throws SQLException {
	    	
	    	
	    	if (args.length < 1) {
	            System.err.print( "Usage: port\n" );
	            System.exit( 1 );
	        }
	
	        int port = Integer.parseInt( args[0] );
	
	        try {
	            ServerSocket s = new ServerSocket( port, 5, InetAddress.getByName( "localhost" ) );
	            System.out.print( "Started server on port " + port + "\n" );
	            waitForClients( s );
	        } catch (Exception e) {
	            System.err.print( "Cannot open socket: " + e );
	            System.exit( 1 );
	        }

    }

}
