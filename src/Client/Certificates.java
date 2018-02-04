package Client;

import java.io.File;
import java.io.FileInputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;



public class Certificates {
	
	Set<Certificate> certs = new HashSet<Certificate>(); //Intermediate certs
	Set<TrustAnchor> ancs = new HashSet<TrustAnchor>(); //Anchors
	static File currentDirectory = new File(new File("").getAbsolutePath());
	static String f = currentDirectory.getAbsolutePath() + "/src/Client";
	Date date = new Date();
	
	//Create a new KeyStore
	public void createCerts() {
		File[] files = new File(f).listFiles();
		CertificateFactory factory;
		
		try {
			factory = CertificateFactory.getInstance("X.509");
			for(File f: files) {
				Certificate c = factory.generateCertificate(new FileInputStream(f));
				X509Certificate xc = (X509Certificate) c;
				PublicKey key = xc.getPublicKey();
				
				//Check self validation
				try {
					xc.verify(key);
					TrustAnchor ta = new TrustAnchor((X509Certificate)xc, null);
					ancs.add(ta);
				}catch(NoSuchAlgorithmException e){
					System.out.println("Algo falhou na criaçºao do cert");
				}catch(SignatureException e) {
					certs.add(xc);
				}
			}
		}catch(Exception e){
			System.out.println("Algo falhou na criaçºao do cert");
		}
		
	}
	
	public boolean validateDate(X509Certificate xc) {
			
		try {
			xc.checkValidity(date);
		}catch(CertificateNotYetValidException | CertificateExpiredException e) {
			return false;
		}
		return true;
	}
	
	public void buildPath(Certificate cft) {
		
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate((X509Certificate) cft);
		
		try {
			
			if(!validateDate((X509Certificate) cft))
				throw new CertificateExpiredException();
			
			PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ancs, selector);
			pkixParams.setRevocationEnabled(false);
			CollectionCertStoreParameters params = new CollectionCertStoreParameters(certs);
			CertStore store = CertStore.getInstance("Collection", params);
			pkixParams.addCertStore(store);
			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
			PKIXCertPathBuilderResult certPath = (PKIXCertPathBuilderResult) builder.build(pkixParams);
			
			CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
			PKIXParameters validationParams = new PKIXParameters(ancs);
			validationParams.setRevocationEnabled(true);
			validationParams.setDate(date);
			
		}catch(Exception e) {
			System.out.println(e);
		}
	}
}
