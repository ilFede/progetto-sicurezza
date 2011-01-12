import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

@SuppressWarnings("unused")
public class Prove {
	
	public static void main(String args[]) throws NoSuchAlgorithmException, TransformerException, ParserConfigurationException, InvalidKeySpecException, ClassNotFoundException, SQLException, UnknownHostException, IOException{
		//esempioChiavi();
		//esempioXML();
		provaChiavi();
		/**
		GregorianCalendar gc = new GregorianCalendar();
		String year = ("0" + gc.get(Calendar.YEAR));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + gc.get(Calendar.MONTH + 1));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + gc.get(Calendar.DAY_OF_MONTH));
		day = day.substring(day.length() - 2, day.length());
		/**String hour = ("0" + gc.get(Calendar.HOUR));
		hour = hour.substring(hour.length() - 2, hour.length());
		String minute = ("0" + gc.get(Calendar.MINUTE));
		minute = minute.substring(minute.length() - 2, minute.length());
		String second = ("0" + gc.get(Calendar.SECOND));
		second = second.substring(second.length() - 2, second.length());*/

		/**Socket conn = new Socket("127.0.0.1", 8888);
		BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		BufferedWriter out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));*/
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
		   /**	//inizializza un generatore di coppie di chiavi usando RSA
	        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	        // genera la coppia
	        KeyPair kp = kpg.generateKeyPair();
	        PrivateKey kpr = kp.getPrivate();
	        String codifica =  CertificateAuthority.convPrivKeyToBase64(kpr);
	        codifica = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCs6116nfqZ5rCMpIEIy1qSss3QWyC3mxzejxAssbiRpMOjlX6Dp2J8HU5KOmIaGZ1RJEdZwRHtXTbJhomXFh3Ke8hqUDoFP3MYNg6PxMSOsYV7ixKaNTe9T0dSUkRea8DHg19yoOJ2HIxylrYq3qtj+U7FKbU+xbqdfZmhGdjX+wIDAQAB";
	        System.out.println("Chiave: " + codifica);
	        PrivateKey kpr2 = CertificateAuthority.convBase64ToPrivKey(codifica);
	        String codifica2 = CertificateAuthority.convPrivKeyToBase64(kpr2);
	        codifica2="MO+/vQHvv70w77+9ARgCAQEwDQYJKu+/vUjvv73vv70NAQECBQAwHjEcMBoGA1UEAxMTVGVzdCBDQSBDZXJ0aWZpY2F0ZTAiGA8xOTIwMDQyOTIyMDAwMFoYDzM5MTEwMTA1MjMwMDAwWjAeMRwwGgYDVQQDExNUZXN0IENBIENlcnRpZmljYXRlMO+/ve+/vTANBgkq77+9SO+/ve+/vQ0BAQEFAAPvv73vv70AMO+/ve+/vQLvv73vv70Ib05MCDk877+977+9PiVa77+9Fu+/ve+/vWLvv71qXSjvv73vv73vv73vv73vv73vv73vv71o77+9Wjp+UO+/ve+/vcuxfe+/vRHvv73vv73vv73vv73vv71w77+9QDzvv70v77+9Pwx3fe+/vRkL77+9DBfvv70c77+977+9D++/ve+/vVdNBSPchHvvv73Sju+/ve+/ve+/vSxp77+9bwzvv73vv70ffu+/vRDvv71KaO+/ve+/vX3vv70N77+977+9K0Tvv71hCO+/vRbvv70aN++/vUzvv73duhUpAO+/ve+/vQIDAQABMA0GCSrvv71I77+977+9DQEBAgUAA++/ve+/vQAAHe+/ve+/ve+/ve+/ve+/vWXvv70x77+977+9W1dC77+9Q++/vVEtawTvv70QC1Xvv73vv73vv70tDB/vv73vv70GU++/ve+/ve+/vTAA15vvv70y77+977+9YgM677+9chrvv73vv73Jsu+/ve+/ve+/vSnvv73vv73vv71fQG3vv73vv73vv70b77+9au+/vW7vv73vv73vv71pau+/vX5NOu+/ve+/vVc4RQVy77+9Pznvv71G77+977+977+977+9d++/vWVKKRgx77+9e23vv73vv73vv709KnNoaVDvv73vv70T77+9C++/ve+/vWzvv70=";
	        System.out.println("Chiave: " + codifica2);
	        System.out.println("Chiavi uguali:" + codifica.equals(codifica2));
	        PublicKey kpp = kp.getPublic();*/
	        String codifica = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJehoqof6JSYs5/rii/xJ36vZjGlQPoV6XSvjDPkoQUC9pNh4s/dGs5lq4CspWooanJSwE88LAuZj6M0oi9wLWkIzSnHlIJI2tniF4Joqhi0unR40kLQ0raL64cA7z8fPJYjxE51Bh6LgRqNq8QA05azmNpQmHw+w60onkz4aAbDAgMBAAECgYAlCiXbGupMijSupvHdnjIAn0X+cJi7vmiFyXAdKQcwWzXycKHgFum6a1mGmCXcFb1S6eXyNQepWbydqHjJz8Q3mIVFWV/JEJTaH87vd8gOoWuT1sW7pRDuAz/Vxez4GgdK+HlPb0NVl+ene8D+ftGUyx4mV1b1jSNkVn5geXhzaQJBANZ80K/UNfCuLNbPzB+bngavv8xTgkNOFAkourAsv6WwCQk/DigP2UIgl7aRl3L/3DXWbVoFMK7XKrnA8PdihM8CQQC0+n6QvKlHPcqBQsQzu25sUMIZxLz1QjDgNv0HJCuqfb5X+C4T5M+OmRzwZHLB7K4/ODVCOVj2Cxe6F0eBhsPNAkA21P28lXGcr8pCuCikw/GoH/HWWFrqveEdXk4rj6UGxHPq6zXBRBv0bcSbJakj+wjesoyOANmrONJxXkO72nG9AkEAmqw3vWWwWzXBO+YfH4OCJUqECVfuksJGWWpFqHPOagDby/1NDC2TAnFznTSMK5cneNqGEhpHIMlsNtwsfdP6xQJAU9qldOs4iEkhlbZiNTzaNJubD7nO3vFkTR0ETKUmye/xSyHy1px1cH9BdASBBiFNPhBChr4vLQ2ml0vUiJLFZg==";
	                          
	        System.out.println("Chiave: " + codifica);
	        PrivateKey kpp2 = CertificateAuthority.convBase64ToPrivKey(codifica);
	        /**codifica2 = CertificateAuthority.convPubKeyToBase64(kpp2);
	        System.out.println("Chiave: " + codifica2);*/
	        System.out.println("Fatto");
	        
	        
	        
	   }

}