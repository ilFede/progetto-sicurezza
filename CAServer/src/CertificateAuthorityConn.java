import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
//import java.sql.Date;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Properties;
import java.util.StringTokenizer;

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
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


public class CertificateAuthorityConn extends DBQuery{
	protected Socket clientConnection;
	protected BufferedReader in;
	protected BufferedWriter out;
	protected X509V2CRLGenerator crlGen;
	protected final String SIGNALG = "DSA";
	private final String GOOD = "good";
	private final String REVOKED = "revoked";
	private final String EXPIRED = "expired";
	private final String CANAME = "FedeCA";
	
	public CertificateAuthorityConn(Socket clientConnection, String dbClassName, String dbPath, Properties dbAccess, X509V2CRLGenerator crlGen) throws SQLException{
		super(dbClassName, dbPath, dbAccess);
		this.clientConnection = clientConnection;
		this.crlGen = crlGen;
		try{
			in = new BufferedReader(new InputStreamReader(clientConnection.getInputStream()));
			out = new BufferedWriter(new OutputStreamWriter(clientConnection.getOutputStream()));
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Metodi per la comunicazione
	
	protected void recieve(){
		try{
			String document = in.readLine();
			decideOperation(document);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	 
	protected void send(Element elem){
		try{
			String xmlString = convXMLToString(elem);
			PrivateKey key = getCaPrivKey();
			String digest = createDigest(xmlString, key);
			String message = "<document>/n" + convXMLToString(elem) + "<digest>" + digest + "</digest>/n</document>";
			out.write(message);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	protected void closeConnection(){
		try{
			in.close();
			out.close();
			clientConnection.close();
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Ricava l'operazione richiesta e la esegue, mancano i controlli del digest
	protected void decideOperation(String message) throws SAXException, IOException, ParserConfigurationException{
		Document doc = convStringToXML(message);
		//doc.getDocumentElement().normalize();
		Node operation = (doc.getElementsByTagName("message").item(0)).getChildNodes().item(0);
		String opName = operation.getNodeName();
		if (opName.equals("getUsrList")){
			getUsrList(message);
		}else if (operation.equals("getCertUsrList")){
			String usr = operation.getChildNodes().item(0).getNodeValue();
			getCertUsrList(message, usr);
		}else if (opName.equals("getOcsp")){
			String cert = operation.getChildNodes().item(0).getNodeValue();
			getOcsp(message, cert);
		}else if (opName.equals("createNewCertificateSS")){
			createNewCertificateSS(message);
		}else if (opName.equals("createNewCertificate")){
			createNewCertificate(message);
		}else if (opName.equals("revokeCert")){
			String cert = operation.getChildNodes().item(0).getNodeValue();
			String reason = operation.getChildNodes().item(1).getNodeValue();
			revokedCert(message, cert, 0);
		}else if (opName.equals("getCrl")){
			sendCRL();
		}
	}
		
	//Operazioni
	
	//Invia la lista di utenti della CA
	protected void getUsrList(String message){
		try{
			boolean b = checkDigest(convStringToXML(message));
			if (b == true){
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		        Document doc = docBuilder.newDocument();
		        //create the root element and add it to the document
		        Element root = doc.createElement("message");
		        root.setAttribute("operation", "usrListResp");
				ResultSet rs = getCAUser();
				while (rs.first()){
					String name = rs.getString(1);
					Element usr = doc.createElement("user");
		            usr.appendChild(doc.createTextNode(name));
		            root.appendChild(usr);
				}
				send(root);
			}else{
				operationError("");
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
		
	}
	
	//Invia la lista dei certificati di un utente
	protected void getCertUsrList(String message, String user){
		try{
			boolean b = checkDigest(convStringToXML(message));
			if (b == true){
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		        Document doc = docBuilder.newDocument();
		        //create the root element and add it to the document
		        Element root = doc.createElement("message");
		        root.setAttribute("operation", "getCertUsrListResp");
				ResultSet rs = getUserValidCert(user);
				while (rs.first()){
					String serial = rs.getString(1);
					String cert = rs.getString(2);
					Element usr = doc.createElement("certUserList");
					usr.setAttribute("serial", serial);
		            usr.appendChild(doc.createTextNode(cert));
		            root.appendChild(usr);
				}
				send(root);
			}else{
				operationError("");
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	
	}
	
	//Invia i dettagli di un certificato da usare come OCSP
	protected void getOcsp(String message, String serialCert){
		try{
			boolean b = checkDigest(convStringToXML(message));
			if (b == true){
				ResultSet rs = getUsrCert(serialCert);
				rs.first();
				String cert = rs.getString(1);
				String state = rs.getString(2);
				String notBefore = rs.getString(3);
				String notAfter = rs.getString(4);
				String serialNumber = rs.getString(5);
				String subjectDN = rs.getString(6);
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	            Document doc = docBuilder.newDocument();
	            //create the root element and add it to the document
	            Element root = doc.createElement("message");
	            root.setAttribute("operation", "getOcspResp");
	            doc.appendChild(root);
	            //create child element and append it
	            Element certEl = doc.createElement("cert");
	            certEl.appendChild(doc.createTextNode(cert));
	            root.appendChild(certEl);
	            Element stateEl = doc.createElement("state");
	            stateEl.appendChild(doc.createTextNode(state));
	            root.appendChild(stateEl);
	            Element notBeforeEl = doc.createElement("notBefore");
	            notBeforeEl.appendChild(doc.createTextNode(notBefore));
	            root.appendChild(notBeforeEl);
	            Element notAfterEl = doc.createElement("notAfter");
	            notAfterEl.appendChild(doc.createTextNode(notAfter));
	            root.appendChild(notAfterEl);
	            Element serialEl = doc.createElement("serialNumber");
	            serialEl.appendChild(doc.createTextNode(serialNumber));
	            root.appendChild(serialEl);
	            Element subjectDNEl = doc.createElement("subjectDN");
	            subjectDNEl.appendChild(doc.createTextNode(subjectDN));
	            root.appendChild(subjectDNEl);
	            send(root);
			}else{
				operationError("");
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
		
	}
	
	//Invia il certificato appena creato sotto richiesta dell'utente
	protected void createNewCertificateSS(String message){
		try{
			Document doc = convStringToXML(message);
			Node certificateData = (doc.getElementsByTagName("createNewCertificateSS")).item(0);
			Date notAfter = convStringToDate(doc.getElementsByTagName("notAfter").item(0).getNodeValue());
			Date notBefore = convStringToDate(doc.getElementsByTagName("notBefore").item(0).getNodeValue());
			String subjectDN = doc.getElementsByTagName("subjectDN").item(0).getNodeValue();
			String publicKey = doc.getElementsByTagName("publicKey").item(0).getNodeValue();
			String signatureAlg = doc.getElementsByTagName("signatureAlg").item(0).getNodeValue();
			String issuerName = CANAME;
			int serial = getFreeSerial();
			
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=Test CA Certificate");

			certGen.setSerialNumber(new BigInteger(serial + ""));
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(notAfter);
			certGen.setNotAfter(notBefore);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(convStringToPubKey(publicKey));
			certGen.setSignatureAlgorithm(signatureAlg);
			X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
			insertUsrCert(); //Controllare con DB
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            Element root = doc.createElement("createNewCertificateSSResp");
            Element certEl = doc.createElement("serial");
            certEl.appendChild(doc.createTextNode(serial + ""));
            root.appendChild(certEl);
            Element stateEl = doc.createElement("cert");
            stateEl.appendChild(doc.createTextNode(convX509ToBase64(cert)));
            root.appendChild(stateEl);
            send(root);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}	
	}
	
	//Invia il certificato appena creato sotto richiesta dell'utente
	protected void createNewCertificate(String message){
		try{
			Document doc = convStringToXML(message);
			Node certificateData = (doc.getElementsByTagName("createNewCertificateSS")).item(0);
			Date notAfter = convStringToDate(doc.getElementsByTagName("notAfter").item(0).getNodeValue());
			Date notBefore = convStringToDate(doc.getElementsByTagName("notBefore").item(0).getNodeValue());
			String subjectDN = doc.getElementsByTagName("subjectDN").item(0).getNodeValue();
			String publicKey = doc.getElementsByTagName("publicKey").item(0).getNodeValue();
			String signatureAlg = doc.getElementsByTagName("signatureAlg").item(0).getNodeValue();
			String issuerName = CANAME;
			int serial = getFreeSerial();
			
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=Test CA Certificate");

			certGen.setSerialNumber(new BigInteger(serial + ""));
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(notAfter);
			certGen.setNotAfter(notBefore);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(convStringToPubKey(publicKey));
			certGen.setSignatureAlgorithm(signatureAlg);
			X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
			insertUsrCert(); //Controllare con DB
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            Element root = doc.createElement("createNewCertificateSSResp");
            Element certEl = doc.createElement("serial");
            certEl.appendChild(doc.createTextNode(serial + ""));
            root.appendChild(certEl);
            Element stateEl = doc.createElement("cert");
            stateEl.appendChild(doc.createTextNode(convX509ToBase64(cert)));
            root.appendChild(stateEl);
            send(root);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}	
	}
	
	protected void revokedCert(String message, String cert, int reason){
		try{
			boolean b = checkDigest(convStringToXML(message));
			if (b == true){
				setStateCert(cert, REVOKED, 0);
				crlGen.addCRLEntry(new BigInteger(cert), getDate(), reason);
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
				DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
				Document doc = docBuilder.newDocument();
				//create the root element and add it to the document
				Element root = doc.createElement("message");
				root.setAttribute("operation", "revokedCertResp");
				Element response = doc.createElement("result");
				response.appendChild(doc.createTextNode("OK"));
				root.appendChild(response);
				send(root);
			}else{
				operationError("");
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	protected void sendCRL(){
		
	}
	
	
	
	//Metodo che invia il messaggio di errore
	protected void operationError(String error){
		
	}
	
	//Metodi per le operazioni
	
	//Crea un certificato
	protected X509Certificate createCert(Date startDate, Date expiryDate, BigInteger serialNumber, KeyPair keyPair, String signatureAlgorithm, X509Certificate caCert, PrivateKey caKey){
		try{
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
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Restituisce la data attuale nel formato Date
	protected static Date getDate(){
		GregorianCalendar gc = new GregorianCalendar();
		int year = gc.get(Calendar.YEAR);
		int month = gc.get(Calendar.MONTH);
		int day = gc.get(Calendar.DAY_OF_MONTH);
		int hrs = gc.get(Calendar.HOUR);
		int min = gc.get(Calendar.MINUTE);
		int sec = gc.get(Calendar.SECOND);
		return new Date(year, month, day, hrs, min, sec);
	}
	
	//Converte unsa Stringa in formato gg/mm/aaaa in util.Date
	protected Date convStringToDate(String s){
		StringTokenizer token = new StringTokenizer(s, "/");
		int day = Integer.parseInt(token.nextToken());
		int month = Integer.parseInt(token.nextToken());
		int year = Integer.parseInt(token.nextToken());
		return new Date (year, month, day);
	}
	
	/**
	//Restituisce la data attuale nel formato Date
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
	 
	 */

	//Metodi per le conversioni delle chiavi

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
	
	//Metodi per i messaggi XML
	
	//Genera la firma base64 di un messaggio
	protected String createDigest(String data, PrivateKey kpriv){
		try{
			Signature s = Signature.getInstance(SIGNALG);
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
			Signature s = Signature.getInstance(SIGNALG);
			s.update(message.getBytes());
			boolean digestOK = false;
			ResultSet certificates = getUserValidCert(sender);
			int col = 0;
			while(certificates.next()){
				col ++;
				PublicKey kpub = convBase64ToX509(certificates.getString(col)).getPublicKey();
				s.initVerify(kpub);
			    if (s.verify(Base64.decode(digest64))){
			    	digestOK = true;
			    }
			}
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
	
	//Restituisce la chiave privata della CA
	protected PrivateKey getCaPrivKey(){
		try{
			ResultSet rs = getCAKeyFromDB();
			rs.first();
			String base64Key = rs.getString(1);
			PrivateKey key = convBase64ToPrivKey(base64Key);
			return key;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Restituisce la chiave pubblica della CA
	protected PublicKey getCaPubKey(){
		try{
			ResultSet rs = getCAKeyFromDB();
			rs.first();
			String base64Key = rs.getString(1);
			PublicKey key = convBase64ToPubKey(base64Key);
			return key;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
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
