import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Hashtable;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import javax.swing.text.Document;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.w3c.dom.*;
//JAXP 1.1
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.stream.*;
import javax.xml.transform.dom.*;
import org.xml.sax.SAXException;
import java.security.cert.X509CRL;
import java.sql.ResultSet;
import java.util.Vector;
import javax.swing.DefaultListModel;
import javax.swing.JList;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.xml.sax.InputSource;

public class Prove {
	
	public static void main(String args[]) throws NoSuchAlgorithmException, TransformerException, ParserConfigurationException, InvalidKeySpecException{
		//esempioChiavi();
		//esempioXML();
		provaChiavi();
	}
	
	public static void esempioChiavi() throws NoSuchAlgorithmException{
		//inizializza un generatore di coppie di chiavi usando RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        System.out.print(".");
        // le chiavi sono molto lunghe: 1024 bit sono 128 byte.
        // La forza di RSA è nell'impossibilità pratica di fattorizzare
        // numeri così grandi.
        kpg.initialize(1024);
        System.out.print(".");
        // genera la coppia
        KeyPair kp = kpg.generateKeyPair();
        System.out.print(". Chiavi generate!\n");
        
        // SALVA CHIAVE PUBBLICA
        
        // ottieni la versione codificata in X.509 della chiave pubblica
        // (senza cifrare)
        byte[] publicBytes = kp.getPublic().getEncoded();
        // salva nel keystore selezionato dall'utente
        String p = new String(publicBytes);
        System.out.println("Chiave pubblica: " + p + "/n");
        
        // SALVA CHIAVE PRIVATA
        
        // ottieni la versione codificata in PKCS#8
        byte[] privateBytes = kp.getPrivate().getEncoded();
        p = new String(privateBytes);
        
        System.out.println("Chiave privata: " + p + "/n");
        String ca = kp.getPrivate().getFormat();
        System.out.println("Format: " + ca);
        System.out.println("Le chiavi sono uguali: " + ca.equals(p));
	}
	
	public static void esempioXML() throws TransformerException, ParserConfigurationException{
		 org.w3c.dom.Document xmldoc = null;
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        DocumentBuilder builder = factory.newDocumentBuilder();
	        DOMImplementation impl = builder.getDOMImplementation();
	        Element e = null;
	        Node n = null;
	        // Document.
	        xmldoc = impl.createDocument(null, "certSigned", null);
	        // Root element.
	        Element root = xmldoc.getDocumentElement();

	        e = xmldoc.createElementNS(null, "serialNumber");
	        n = xmldoc.createTextNode("ciao");
	            e.appendChild(n);
	            root.appendChild(e);
	        e = xmldoc.createElementNS(null, "notBefore");
	        n = xmldoc.createTextNode("come");
	            e.appendChild(n);
	            root.appendChild(e);
	        e = xmldoc.createElementNS(null, "notAfter");
	        n = xmldoc.createTextNode("stai?");
	            e.appendChild(n);
	            root.appendChild(e);
	            
	        e = xmldoc.createElementNS(null, "afdadsad");
		    n = xmldoc.createTextNode("Hey!!");
		        e.appendChild(n);
	            e.appendChild(xmldoc.getDocumentElement());
	        // Serialisation through Tranform.
	        DOMSource domSource = new DOMSource(xmldoc);

	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer trans = tf.newTransformer();
	        StringWriter sw = new StringWriter();
	        trans.transform((domSource), new StreamResult(sw));
	        String theAnswer = sw.toString();
	        System.out.println(theAnswer);
	        aggancia(xmldoc);
	   }
	
		private static void aggancia(org.w3c.dom.Document doc) throws ParserConfigurationException, TransformerException{
			org.w3c.dom.Document xmldoc = null;
	        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	        DocumentBuilder builder = factory.newDocumentBuilder();
	        DOMImplementation impl = builder.getDOMImplementation();
	        Element e = null;
	        Node n = null;
	        // Document.
	        xmldoc = impl.createDocument(null, "ciao", null);
	        // Root element.
	        Element root = xmldoc.getDocumentElement();
	        e = xmldoc.createElementNS(null, "afdadsad");
		    n = xmldoc.createTextNode("Hey!!");
		        e.appendChild(n);
	            root.appendChild(e);
	        root.appendChild(doc);    
	        // Serialisation through Tranform.
	        DOMSource domSource = new DOMSource(xmldoc);

	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer trans = tf.newTransformer();
	        StringWriter sw = new StringWriter();
	        trans.transform((domSource), new StreamResult(sw));
	        String theAnswer = sw.toString();
	        System.out.println(theAnswer);
			
		}
	
	   private static void provaChiavi() throws NoSuchAlgorithmException, InvalidKeySpecException{
		   	//inizializza un generatore di coppie di chiavi usando RSA
	        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	        // genera la coppia
	        KeyPair kp = kpg.generateKeyPair();
	        PrivateKey kpr = kp.getPrivate();
	        String codifica =  CertificateAuthority.convPrivKeyToBase64(kpr);
	        System.out.println("Chiave: " + codifica);
	        PrivateKey kpr2 = CertificateAuthority.convBase64ToPrivKey(codifica);
	        String codifica2 = CertificateAuthority.convPrivKeyToBase64(kpr2);
	        System.out.println("Chiave: " + codifica2);
	        System.out.println("Chiavi uguali:" + codifica.equals(codifica2));
	        PublicKey kpp = kp.getPublic();
	        codifica =  CertificateAuthority.convPubKeyToBase64(kpp);
	        System.out.println("Chiave: " + codifica);
	        PublicKey kpp2 = CertificateAuthority.convBase64ToPubKey(codifica);
	        codifica2 = CertificateAuthority.convPubKeyToBase64(kpp2);
	        System.out.println("Chiave: " + codifica2);
	        System.out.println("Chiavi uguali:" + codifica.equals(codifica2));
	        
	        
	        
	   }

}
