import java.io.*;
import java.net.*;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.math.BigInteger;
import java.security.*;

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

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Properties;
import java.util.StringTokenizer;

public class ClientCA extends DBQueryClient{
	protected static int num;
	protected int id;
	protected Socket conn;
	protected BufferedReader in;
	protected BufferedWriter out;
	protected String user;
	protected PublicKey caPubKey;
	protected final String DIGEST_SIGN_ALG = "DSA";
	protected final String GOOD = "good";
	protected final String REVOKED = "revoked";
	protected final String EXPIRED = "expired";
	protected final String CANAME = "FedeCA";
	protected final String CRL_SIGN_ALG = "MD2withRSA";
	
	//Costruttore
	public ClientCA(String dbClassName, String dbPath, Properties dbAccess, String host, int port) throws SQLException{
		super(dbClassName, dbPath, dbAccess);
		try{
			Socket conn = new Socket(host, port);
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));	
			caPubKey = recieveCaPubKey();
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
		id = num;
		num+=1; 
		System.out.println("Il numero è: " + num);
		String user = getUsername().getString(1);
	}
	
	//Metodi per la comunicazione col server
	
	//Riceve un messaggio
	protected void recieve(){
		try{
			String document = in.readLine();
			//decideOperation(document);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Invia un messaggio firmandolo
	protected void sendWithDigest(Element elem, PrivateKey privKey){
		try{
			String xmlString = convXMLToString(elem);
			PrivateKey key = privKey;
			String digest = createDigest(xmlString, key);
			String message = "<document>/n" + convXMLToString(elem) + "<digest>" + digest + "</digest>/n</document>";
			out.write(message);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Invia un messaggio senza firma
	protected void sendWithoutDigest(Element elem){
		try{
			String xmlString = convXMLToString(elem);
			String message = "<document>/n" + convXMLToString(elem) + "/n</document>";
			out.write(message);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Operazioni
	
	//Ottiene la chiave pubblica della CA
	protected PublicKey recieveCaPubKey(){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendCaPubKey");
			sendWithoutDigest(root);
			String document = in.readLine();
			Document response = convStringToXML(document);
			Node message = (response.getElementsByTagName("message").item(0));
			String caPubKeyString = message.getChildNodes().item(0).getTextContent();
			return convStringToPubKey(caPubKeyString);
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
		
	}
	
	//Riceve la lista degli utenti
	protected ArrayList<String> recieveUrsList(){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendUsrList");
			sendWithoutDigest(root);
			
			String document = in.readLine();
			Document response = convStringToXML(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				Node message = (response.getElementsByTagName("message").item(0));
				return convXmlToArrayList(message);
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Riceve la lista dei certificati validi di un utente
	protected ArrayList<String> recieveCertUsrList(){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendOcsp");
			sendWithoutDigest(root);
			
			String document = in.readLine();
			Document response = convStringToXML(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				Node message = (response.getElementsByTagName("message").item(0));
				return convXmlToArrayList(message);
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Riceve l'ocsp di un certificato
	protected ArrayList<String> recieveOcsp(String serial){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendOcsp");
			Element el = doc.createElement("serial");
            el.appendChild(doc.createTextNode(serial));
			root.appendChild(el);

			sendWithoutDigest(root);
			
			String document = in.readLine();
			Document response = convStringToXML(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				Node message = (response.getElementsByTagName("message").item(0));
				return convXmlToArrayList(message);
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Richeide un nuovo certificato autofirmato
	protected void certificateSSRequest(String notAfter, String notBefore, String subjectDN, String signatureAlg, String organizationUnit, int l){
		try{
			KeyPair kp = createKeyPair(l);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "createNewCertificateSS");
			Element nb = doc.createElement("notBefore");
	        nb.appendChild(doc.createTextNode(notBefore));
			root.appendChild(nb);
			Element na = doc.createElement("notAfter");
	        na.appendChild(doc.createTextNode(notAfter));
			root.appendChild(na);
			Element sDN = doc.createElement("notBefore");
	        sDN.appendChild(doc.createTextNode(notBefore));
			root.appendChild(sDN);
			Element pk = doc.createElement("publicKey");
	        pk.appendChild(doc.createTextNode(convPubKeyToBase64(kp.getPublic())));
			root.appendChild(pk);
			Element sigAl = doc.createElement("signatureAlg");
	        sigAl.appendChild(doc.createTextNode(signatureAlg));
			root.appendChild(sigAl);
			Element ou = doc.createElement("OrganizationUnit");
	        ou.appendChild(doc.createTextNode(organizationUnit));
			root.appendChild(ou);
			sendWithoutDigest(root);
			String document = in.readLine();
			Document response = convStringToXML(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				String serial = (response.getElementsByTagName("serial").item(0)).getNodeValue();
				String cert = (response.getElementsByTagName("cert").item(0)).getNodeValue();
				//--------------- Inserire nel DB ----------
			}else{
				System.out.println("firma non valida");
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Richeide un nuovo certificato autofirmato
	protected void certificateRequest(String notAfter, String notBefore, String subjectDN, String signatureAlg, String organizationUnit, int l, String pkserial){
		try{
			KeyPair kp = createKeyPair(l);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "createNewCertificateSS");
			Element nb = doc.createElement("notBefore");
	        nb.appendChild(doc.createTextNode(notBefore));
			root.appendChild(nb);
			Element na = doc.createElement("notAfter");
	        na.appendChild(doc.createTextNode(notAfter));
			root.appendChild(na);
			Element sDN = doc.createElement("notBefore");
	        sDN.appendChild(doc.createTextNode(notBefore));
			root.appendChild(sDN);
			Element pk = doc.createElement("publicKey");
	        pk.appendChild(doc.createTextNode(convPubKeyToBase64(kp.getPublic())));
			root.appendChild(pk);
			Element sigAl = doc.createElement("signatureAlg");
	        sigAl.appendChild(doc.createTextNode(signatureAlg));
			root.appendChild(sigAl);
			Element ou = doc.createElement("OrganizationUnit");
	        ou.appendChild(doc.createTextNode(organizationUnit));
			root.appendChild(ou);
			ResultSet rs = getPrivKeyToDB(pkserial);
			rs.first();
			PrivateKey privk = convStringToPrivKey(rs.getString(1));
			sendWithDigest(root, privk);
			String document = in.readLine();
			Document response = convStringToXML(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				String serial = (response.getElementsByTagName("serial").item(0)).getNodeValue();
				String cert = (response.getElementsByTagName("cert").item(0)).getNodeValue();
				//--------------- Inserire nel DB ----------
			}else{
				System.out.println("firma non valida");
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
	
			
	public void closeConnection() throws IOException{
		in.close();
		out.close();
		conn.close();
	}
	
	public void send (String s) throws IOException{
		out.write("Client " + num + ": ");
		out.write(s);
		out.newLine();
		out.flush();
	}
	
	//Metodi per esegiure le operazioni
	
	private KeyPair createKeyPair(int l) throws NoSuchAlgorithmException{
		//inizializza un generatore di coppie di chiavi usando RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(l);
        // genera la coppia
        KeyPair kp = kpg.generateKeyPair();
        return kp;
	}
		
	
    //Metodi per i messaggi XML
	
	//Genera la firma base64 di un messaggio
	protected String createDigest(String data, PrivateKey kpriv){
		try{
			Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
			s.initSign(kpriv);
			s.update(data.getBytes());
			byte[] signature = s.sign();
			return new String(Base64.encode(signature));
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Controlla la firma di un messaggio
	protected boolean checkDigest(Document doc){
		try{
			String message = getMessage(doc);
			String digest64 = getDigest64(doc);
			String sender = getSender(doc);
			Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
			s.update(message.getBytes());
			s.initVerify(caPubKey);
			boolean digestOK = s.verify(Base64.decode(digest64));
			return digestOK;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	//Restituisce la stringa rappresentante il messaggio
	protected String getMessage(Document doc){
		try{
			//doc.getDocumentElement().normalize();
			Node messageNode = (doc.getElementsByTagName("message").item(0));
			//Create a transformer
			TransformerFactory transfac = TransformerFactory.newInstance();
			Transformer trans = transfac.newTransformer();
			trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			trans.setOutputProperty(OutputKeys.INDENT, "yes");
			//create file from xml tree
			StringWriter sw = new StringWriter();
			StreamResult result = new StreamResult(sw);
			DOMSource messageSouce = new DOMSource(messageNode);
			trans.transform(messageSouce, result);
			String message = sw.toString();
			return message;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Restituisce la stringa BASE64 rappresentante la firma
	protected String getDigest64(Document doc){
		try{
			//doc.getDocumentElement().normalize();
			Node digestNode = (doc.getElementsByTagName("digest").item(0));
			//Create a transformer
			TransformerFactory transfac = TransformerFactory.newInstance();
			Transformer trans = transfac.newTransformer();
			trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			trans.setOutputProperty(OutputKeys.INDENT, "yes");
			//create file from xml tree
			StringWriter sw = new StringWriter();
			StreamResult result = new StreamResult(sw);
			DOMSource messageSouce = new DOMSource(digestNode.getFirstChild());
			trans.transform(messageSouce, result);
			String message = sw.toString();
			return message;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Restituisce la stringa rappresentante il mittente del messaggio
	protected String getSender(Document doc){
		try{
			//doc.getDocumentElement().normalize();
			NamedNodeMap attrs = (doc.getElementsByTagName("document").item(0)).getAttributes();
			Node senderNode = attrs.getNamedItem ("sender");
			String sender = senderNode.getNodeValue();
			return sender;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
    //Metodi per le conversioni varie
	
	//Converte unsa Stringa in formato gg/mm/aaaa in util.Date
	protected Date convStringToDate(String s){
		StringTokenizer token = new StringTokenizer(s, "/");
		int day = Integer.parseInt(token.nextToken());
		int month = Integer.parseInt(token.nextToken());
		int year = Integer.parseInt(token.nextToken());
		return new Date (year, month, day);
	}
	
	//Converte un Date in formato gg/mm/aaaa
	protected String getStringDate(Date date){
		String year = ("0" + date.getYear());
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + date.getMonth());
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + date.getDay());
		day = day.substring(day.length() - 2, day.length());
		return day + "/" + month + "/" + year;
	}
	
	//Converte una stringa in una chiave pubblica
	protected static PublicKey convStringToPubKey(String publicKey){
		try{
			byte[] publicKeyBytes = publicKey.getBytes();
			X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(ks);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte una stringa in una chiave privata
	protected static PrivateKey convStringToPrivKey(String privateKey){
		try{
			byte[] privateKeyBytes = privateKey.getBytes();
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(ks);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte una stringa BASE64 in una chiave pubblica
	protected static PublicKey convBase64ToPubKey(String publicKey){
		try{
			byte[] publicKeyBytes =  Base64.decode(publicKey);
			X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(ks);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte una stringa BASE64 in una chiave privata
	protected static PrivateKey convBase64ToPrivKey(String privateKey){
		try{
			byte[] privateKeyBytes = Base64.decode(privateKey);
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(ks);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//converte una chiave privata in una stringa
	protected static String convPrivKeyToString(PrivateKey key){
		return new String(Base64.encode(key.getEncoded()));
	}
	
	//converte una chiave pubblica in una stringa
	protected static String convPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}
	
	//converte una chiave pubblica in una stringa BASE64
	protected static String convPubKeyToBase64(PublicKey key){
		return new String(Base64.encode(key.getEncoded()));
	}
	
	//converte una chiave privata in una stringa BASE64
	protected static String convPrivKeyToBase64(PrivateKey key){
		return new String(key.getEncoded());
	}

	//Converte una stringa in un Document XML
	protected Document convStringToXML(String s) throws SAXException, IOException, ParserConfigurationException{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder parser = factory.newDocumentBuilder();
	    Document d = parser.parse(new ByteArrayInputStream(s.getBytes()));
	    return d;
	}
	
	//Converte un Document XML in una stringa
	protected String convXMLToString (Element doc) throws TransformerException{
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
	
	//Converte un resultSet in un Vector
	protected ArrayList<String> convXmlToArrayList(Node node){
		NodeList nl = node.getChildNodes();
		ArrayList<String> array = new ArrayList<String>();
		int l = nl.getLength();
		for(int i = 0; i < l; i++){
			array.add(nl.item(i).getNodeValue());
		}
		return array;
	}
	
	//Metodi per le conversioni dei certificati
	
	//Converte un certificato dal formato X509V3 a XML
	protected String convX509ToXML (X509Certificate certSigned){
		try{
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
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	
	//Converte una certificato in una stringa base 64
	protected String convX509ToBase64(X509Certificate cert){
		try{
			String strCert = new String(cert.getEncoded());
			byte[] byteBase64 = Base64.encode(strCert.getBytes());
			return new String(byteBase64);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte una stringa base64 iu un certificato
	protected X509Certificate convBase64ToX509(String base64Cert){
		try{
			byte[] byteCert = Base64.decode(base64Cert.getBytes());
			CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
			X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(byteCert));
			return cert;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte un X509CRL in Base64
	protected String convCrlToBase64(X509CRL crl){
		try{
			byte[] crlByte = crl.getEncoded();
			byte[] clrBase64 = Base64.encode(crlByte);
			return new String(clrBase64);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	/**public static void main(String args[]) throws UnknownHostException, IOException{
		ClientCA client = new ClientCA();
		client.getConnection("127.0.0.1", 9999);
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Client " + client.id +  ": ");
		String s = reader.readLine();
		while (!s.equals("stop")){
			client.send(s);
			System.out.print("Client " + client.id +  ": ");
			s = reader.readLine();
		}
		client.closeConnection();
		
	}*/
}