package Client;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;



public class ccReader {

	static File currentDirectory = new File(new File("").getAbsolutePath());
	static String f = currentDirectory.getAbsolutePath() + "/src/Client/CartaoCidadao.cfg";

	public void main(String[] args) {
		Provider p = new sun.security.pkcs11.SunPKCS11( f );
		Security.addProvider(p);
		   
	}
	
	public static String getBI(){
		try{
			return read().split("SERIALNUMBER=")[1].split(",")[0].split("BI")[1];
		}
		catch(Exception e){
			return null;
		}
	}
	
	public static byte[] getPublicKey() throws Exception{
		Provider p = new sun.security.pkcs11.SunPKCS11( f );
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-PTeID" );
        ks.load(null,null);
        java.security.cert.Certificate c = ks.getCertificate("CITIZEN AUTHENTICATION CERTIFICATE");
        PublicKey pk = c.getPublicKey();
        return pk.getEncoded();
	}
	
	public static PrivateKey getPrivateKey() throws Exception{
	
		Provider p = new sun.security.pkcs11.SunPKCS11( f );
        Security.addProvider(p);
        KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-PTeID" );
        ks.load(null,null);
        String alias = "CITIZEN AUTHENTICATION CERTIFICATE";
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, null);
        
        return privateKey;
	}
	
	public static String read(){
		try{
			Provider p = new sun.security.pkcs11.SunPKCS11( f );
			Security.addProvider( p );
			
			KeyStore ks = KeyStore.getInstance( "PKCS11", "SunPKCS11-PTeID" );
			ks.load( null, null );
			
			String everything = "";
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				Object alias = aliases.nextElement();
		        X509Certificate cert0 = (X509Certificate) ks.getCertificate(alias.toString());
		        everything += "\n" + cert0.getSubjectDN().getName();
			 }
			
			return everything;
		}catch(Exception e){
			return null;
		}
	}
}
