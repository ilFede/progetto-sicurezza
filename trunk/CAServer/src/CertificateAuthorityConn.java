import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Date;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


public class CertificateAuthorityConn extends DBQuery{
	protected Socket clientConnection;
	protected BufferedReader in;
	protected BufferedWriter out;
	protected final String SIGNALG = "DSA";
	
	public CertificateAuthorityConn(Socket clientConnection, String dbClassName, String dbPath, Properties dbAccess) throws IOException, SQLException{
		super(dbClassName, dbPath, dbAccess);
		this.clientConnection = clientConnection;
		in = new BufferedReader(new InputStreamReader(clientConnection.getInputStream()));
		out = new BufferedWriter(new OutputStreamWriter(clientConnection.getOutputStream()));		
	}
	
	//Metodi per la comunicazione
	
	protected String recieve() throws IOException{
		String s = in.readLine();
		return s;
	}
	 
	protected void send(String s) throws IOException{
		out.write(s);
	}
	
	protected void closeConnection() throws IOException{
		in.close();
		out.close();
		clientConnection.close();
	}
	
	//Ricava l'operazione richiesta
	protected void esegui(String operation) throws SAXException, IOException, ParserConfigurationException{
		Document doc = convStringToXML(operation);
		
	}
	//Metodi per le operazioni
	
	//Crea un certificato
	protected X509Certificate createCert(Date startDate, Date expiryDate, BigInteger serialNumber, 
			KeyPair keyPair, String signatureAlgorithm, X509Certificate caCert, PrivateKey caKey) throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateParsingException{
		//Modificare in modo che basti passare lo statement del database
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm(signatureAlgorithm);
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.getPublic()));
		X509Certificate cert = certGen.generate(caKey, "BC");   // note: private key of CA
		return cert;
	}
	
	//Genera la firma base64 di un messaggio
	protected String createDigest(String data, PrivateKey kpriv) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException{
		Signature s = Signature.getInstance(SIGNALG);
		s.initSign(kpriv);
		s.update(data.getBytes());
		byte[] signature = s.sign();
		return new String(Base64.encode(signature));
	}
	
	//Controlla la firma di un messaggio
	protected boolean checkDigest(String mess, String digest64, PublicKey kpub) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature s = Signature.getInstance(SIGNALG);
		s.initVerify(kpub);
		s.update(mess.getBytes());
		return s.verify(Base64.decode(digest64));
	}
	
	//Restituisce la data attuale nel forato AAAA/M/GG HH:MM:SS
	protected static String getDate(){
		GregorianCalendar gc = new GregorianCalendar();
		String year = ("0" + gc.get(Calendar.YEAR));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + gc.get(Calendar.MONTH));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + gc.get(Calendar.DAY_OF_MONTH));
		day = day.substring(day.length() - 2, day.length());
		String hour = ("0" + gc.get(Calendar.HOUR));
		hour = hour.substring(hour.length() - 2, hour.length());
		String minute = ("0" + gc.get(Calendar.MINUTE));
		minute = minute.substring(minute.length() - 2, minute.length());
		String second = ("0" + gc.get(Calendar.SECOND));
		second = second.substring(second.length() - 2, second.length());
		return year + "/" + month + "/" + day + " " + hour + ":" + minute + ":" + second + ":00";
	}

	//Metodi per le conversioni

	//Converte una stringa in una chiave pubblica
	protected static PublicKey convStringToPubKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] publicKeyBytes = publicKey.getBytes();
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
	}
	
	//Converte una string in una chiave privata
	protected static PrivateKey convStringToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] privateKeyBytes = privateKey.getBytes();
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
	}
	
	//Converte una stringa in un Document XML
	protected Document convStringToXML(String s) throws SAXException, IOException, ParserConfigurationException{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder parser = factory.newDocumentBuilder();
	    Document d = parser.parse(new ByteArrayInputStream(s.getBytes()));
	    return d;
	}
	
	//Converte un Document XML in una stringa
	protected String convXMLToString (Document doc) throws TransformerException{
        TransformerFactory transfac = TransformerFactory.newInstance();
        Transformer trans = transfac.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        trans.setOutputProperty(OutputKeys.INDENT, "yes");
        //create string from xml tree
        StringWriter sw = new StringWriter();
        StreamResult result = new StreamResult(sw);
        DOMSource source = new DOMSource(doc);
        trans.transform(source, result);
        String xmlString = sw.toString();
        return xmlString;
	}
	
	//converte una chiave privata in una stringa
	protected static String convPrivKeyToString(PrivateKey key){
		return new String(key.getEncoded());
	}
	
	//converte una chiave pubblica in una stringa
	protected static String convPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}
	
	//Converte un certificato dal formato X509V3 a XML
	protected String convX509ToXML (X509Certificate certSigned) throws CertificateEncodingException, ParserConfigurationException, TransformerException{
		org.w3c.dom.Document xmldoc = null;
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        DOMImplementation impl = builder.getDOMImplementation();
        Element elem = null;
        Node n = null;
        // Document.
        xmldoc = impl.createDocument(null, "certSigned", null);
        // Root element.
        Element root = xmldoc.getDocumentElement();
        elem = xmldoc.createElementNS(null, "serialNumber");
        n = xmldoc.createTextNode(certSigned.getSerialNumber().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "notBefore");
        n = xmldoc.createTextNode(certSigned.getNotBefore().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "notAfter");
        n = xmldoc.createTextNode(certSigned.getNotAfter().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "issuerDN");
        n = xmldoc.createTextNode(certSigned.getIssuerDN().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "subjectDN");
        n = xmldoc.createTextNode(certSigned.getSubjectDN().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "signAlgName");
        n = xmldoc.createTextNode(certSigned.getSigAlgName().toString());
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "signatureEncoded");
        String base64Signature = new String(Base64.encode(certSigned.getSignature()));
        n = xmldoc.createTextNode(base64Signature);
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "publicKey");
        n = xmldoc.createTextNode(convPubKeyToString(certSigned.getPublicKey()));
        elem.appendChild(n);
        root.appendChild(elem);
        elem = xmldoc.createElementNS(null, "certSignEncoded");
        String base64certEncoding = new String(Base64.encode(certSigned.getEncoded()));
        n = xmldoc.createTextNode(base64certEncoding);
        elem.appendChild(n);
        root.appendChild(elem);
        DOMSource domSource = new DOMSource(xmldoc);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        StringWriter sw = new StringWriter();
        trans.transform((domSource), new StreamResult(sw));
        String theAnswer = sw.toString();
        System.out.println(theAnswer);
        return theAnswer;//return the string
	}
	
	
	//Converte una certificato in una stringa base 64
	protected String convX509ToBase64(X509Certificate cert) throws CertificateEncodingException{
        String strCert = new String(cert.getEncoded());
        byte[] byteBase64 = Base64.encode(strCert.getBytes());
        return new String(byteBase64);
	}
	
	//Converte una stringa base64 iu un certificato
	protected X509Certificate convBase64ToX509(String base64Cert) throws CertificateException, NoSuchProviderException{
		byte[] byteCert = Base64.decode(base64Cert.getBytes());
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(byteCert));
        return cert;
	}
	
	/**public X509Certificate convXMLToX509v3(String xmlString) throws ParserConfigurationException, IOException, SAXException, CertificateException, NoSuchProviderException {
        org.w3c.dom.Document d = stringToXMLDocument(xmlString);
        Element e = d.getDocumentElement();
        NodeList e1 = e.getChildNodes();
        Node serialNTag = e1.item(0);
        Node notBeforeTag = e1.item(1);
        Node notAfterTag = e1.item(2);
        Node issuerDNTag = e1.item(3);
        Node subjectDNTag = e1.item(4);
        Node signAlgNameTag = e1.item(5);
        Node signatureTag = e1.item(6);
        Node publicKeyTag = e1.item(7);
        Node certEncodedTag = e1.item(8);

        byte[] data = Base64.decode(certEncodedTag.getTextContent());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        return (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(data));
    }
	
	//Controllare	
	public org.w3c.dom.Document stringToXMLDocument(String xmlstring) throws SAXException, IOException, ParserConfigurationException{
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder parser = factory.newDocumentBuilder();
        StringReader stringStream = new StringReader(xmlstring.trim());
        InputSource is = new InputSource(stringStream);

        //org.w3c.dom.Document d = parser.parse(new ByteArrayInputStream(xmlstring.getBytes()));
        org.w3c.dom.Document d = parser.parse(is);
        return d;

    }*/
	
}
