// Fare in modo che sia il gestore delle operazioni a gestire le eccezioni, mandando in caso negativo un messaggio di errore standared firmato

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;
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
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
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

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.w3c.dom.DOMException;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


public class ServerCAConn extends Thread{
	protected Socket clientConnection;
	protected BufferedReader in;
	protected PrintStream out;
	protected X509V2CRLGenerator crlGen;
	protected final String DIGEST_SIGN_ALG = "MD2withRSA";
	protected final String GOOD = "good";
	protected final String REVOKED = "revoked";
	protected final String EXPIRED = "expired";
	protected final String CANAME = "FedeCA";
	protected final String CRL_SIGN_ALG = "MD2withRSA";
	protected final String OP_FAIL = "fail";
	//private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
	private int lastSerial; //primo seriale non usato, viene salvato in una cella del DB
	//private final String GOOD = "good";
	//private final String EXPIRED = "expired";
	
	public void run(){
		try {
			System.out.println("Un theread è partito!!");
			recieve();
		} catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	public ServerCAConn(Socket clientConnection, String dbClassName, String dbPath, X509V2CRLGenerator crlGen) throws SQLException, ClassNotFoundException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		System.out.println(dbClassName);
		System.out.println(dbPath);
		System.out.println(this.dbClassName + this.dbPath);
		Class.forName("org.sqlite.JDBC"); 
		//conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		//System.out.println("only red " + conn.isReadOnly());
	    //Statement stm = conn.createStatement();
		this.clientConnection = clientConnection;
		this.crlGen = crlGen;
		try{
			in = new BufferedReader(new InputStreamReader(clientConnection.getInputStream()));
			out = new PrintStream(clientConnection.getOutputStream());
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Metodi per la comunicazione
	
	//Riceve un messaggio
	protected void recieve() throws IOException, SAXException, ParserConfigurationException{
		System.out.println("Messaggio in lettura");
		while(!in.ready()){
		}
        String document = in.readLine();
        while(in.ready()){
        	document = document + "\n" + in.readLine();
        }
		System.out.println("Messaggio ricevuto\n" + document);

		decideOperation(document);
		recieve();
	}
	
	//Invia un messaggio firmandolo
	protected void sendWithDigest(Element elem) throws TransformerException, IOException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, SQLException{
		String xmlString = convXMLToString(elem);
		System.out.println("Tento la seconda");
		PrivateKey key = getCaPrivKey();
		System.out.println("Ho fatto la seconda");
		String digest = createDigest(xmlString, key);
		String message = "<document>\n" + convXMLToString(elem) + "<digest>\n" + digest + "\n</digest>\n</document>";
		System.out.println(message);
		out.println(message);
		System.out.println("Messaggio spedito");
	}
	
	//Invia un messaggio senza firmarlo
	protected void sendWithoutDigest(Element elem) throws TransformerException, IOException{	
		//String xmlString = convXMLToString(elem);
		String message = "<document>\n" + convXMLToString(elem) + "</document>";
		System.out.println(message);
		out.println(message);
		System.out.println("Messaggio spedito");
	}
	
	//Invia un messaggio di fallita operazione
	protected void sendFailure(String opName) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, TransformerException, IOException, SQLException, ParserConfigurationException{
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc2 = docBuilder.newDocument();
		Element root = doc2.createElement("opName");
        Element certEl = doc2.createElement("esit");
        certEl.appendChild(doc2.createTextNode("false"));
        root.appendChild(certEl);
        sendWithDigest(root);
	}
	
	
	protected void closeConnection() throws IOException{
			in.close();
			out.close();
			clientConnection.close();
	}
	
	//Ricava l'operazione richiesta e la esegue, mancano i controlli del digest
	protected void decideOperation(String message){
		try{
			Document doc = convStringToXml(message);
			//doc.getDocumentElement().normalize();
			Node messNode = (doc.getElementsByTagName("message").item(0));
			Node opNode = messNode.getAttributes().item(0);
			String opName = opNode.getNodeValue();
			System.out.println("Operazione server: " + opName);
			try{
				if (opName.equals("sendUsrList")){
					sendUsrList(message);
				}else if (messNode.equals("sendCertUsrList")){
					String usr = messNode.getChildNodes().item(0).getNodeValue();
					sendCertUsrList(message, usr);
				}else if (messNode.equals("sendHaveValidCert")){
					String usr = messNode.getChildNodes().item(0).getNodeValue();
					sendHaveValidCert(message, usr);
				}else if (opName.equals("sendOcsp")){
					String cert = messNode.getChildNodes().item(0).getNodeValue();
					sendOcsp(message, cert);
				}else if (opName.equals("createNewCertificateSS")){
					createNewCertificateSS(message);
				}else if (opName.equals("createNewCertificate")){
					createNewCertificate(message);
				}else if (opName.equals("revokeCert")){
					String cert = messNode.getChildNodes().item(0).getNodeValue();
					String reason = messNode.getChildNodes().item(1).getNodeValue();
					revokedCert(message, cert, Integer.parseInt(reason));
				}else if (opName.equals("renewCert")){
					String cert = messNode.getChildNodes().item(0).getNodeValue();
					String newNotBefore = messNode.getChildNodes().item(1).getNodeValue();
					String publicKey = messNode.getChildNodes().item(2).getNodeValue();
					renewCert(message, cert, newNotBefore, publicKey);
				}else if (opName.equals("sendCrl")){
					sendCRL();
				}else if (opName.equals("insertNewUser")){
					String usr = doc.getElementsByTagName("user").item(0).getChildNodes().item(0).getNodeValue();					System.out.println("utente: " + usr);
					insertNewUser(usr);
				}else if (opName.equals("sendCaPubKey")){
					sendCaPubKey();
				}else if (opName.equals("checkUser")){
					String usr = doc.getElementsByTagName("user").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("Chiamo ckeck user su " + usr);
					checkUsr(usr);
				}
			}catch(Exception e){
				System.out.println(e.getMessage());
				sendFailure(opName + "Resp");	
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
		
	//Operazioni
	
	//Invia la lista di utenti della CA
	protected void sendUsrList(String message) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message));
		conn.close();
		if (b == true){
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc = docBuilder.newDocument();
	        //create the root element and add it to the document
	        Element root = doc.createElement("message");
	        root.setAttribute("operation", "sendUsrListResp");
	        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getCAUser();
			while (rs.next()){
				String name = rs.getString(1);
				Element usr = doc.createElement("user");
	            usr.appendChild(doc.createTextNode(name));
	            root.appendChild(usr);
			}
			conn.close();
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendUsrListResp");
			conn.close();
		}
	}
	
	//Invia la lista dei certificati di un utente
	protected void sendCertUsrList(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message));
		conn.close();
		if (b == true){
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc = docBuilder.newDocument();
	        //create the root element and add it to the document
	        Element root = doc.createElement("message");
	        root.setAttribute("operation", "sendCertUsrListResp");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getAllUserCert(user);
			while (rs.next()){
				String serial = rs.getString(1);
				String cert = rs.getString(2);
				Date notBefore = convStringToDate(rs.getString(4));
				Date now = getDate();
				if (now.compareTo(notBefore) <= 0){
					Element usr = doc.createElement("certUserList");
					usr.setAttribute("serial", serial);
					usr.appendChild(doc.createTextNode(cert));
					root.appendChild(usr);
				}
			}
			conn.close();
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendCertUsrListResp");
			conn.close();
		}	
	}
	//Invia la lista dei certificati di un utente
	protected void sendHaveValidCert(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		//boolean b = checkDigest(convStringToXml(message));
		boolean b = true;
		conn.close();
		if (b == true){
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc = docBuilder.newDocument();
	        //create the root element and add it to the document
	        Element root = doc.createElement("message");
	        root.setAttribute("operation", "sendHaveValidCertResp");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getValidUserCert(user);
			boolean value = rs.next();
			Element elem = doc.createElement("result");
			elem.appendChild(doc.createTextNode(value + ""));
			root.appendChild(elem);
			conn.close();
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendHaveValidCertResp");
			conn.close();
		}	
	}
	
	//Invia i dettagli di un certificato da usare come OCSP
	protected void sendOcsp(String message, String serialCert) throws SQLException, ParserConfigurationException, SAXException, IOException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message));
		conn.close();
		if (b == true){
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
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
            root.setAttribute("operation", "sendOcspResp");
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
            conn.close();
            conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
            sendWithDigest(root);
            conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendOcspResp");
			conn.close();
		}
	}
	
	//Invia il certificato self signed appena creato sotto richiesta dell'utente
	protected void createNewCertificateSS(String message) throws SAXException, IOException, ParserConfigurationException, SQLException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, TransformerException, InvalidKeySpecException{
		Document doc1 = convStringToXml(message);
		Date notAfter = convStringToDate(doc1.getElementsByTagName("notAfter").item(0).getNodeValue());
		Date notBefore = convStringToDate(doc1.getElementsByTagName("notBefore").item(0).getNodeValue());
		String subjectDN = doc1.getElementsByTagName("subjectDN").item(0).getNodeValue();
		String publicKey = doc1.getElementsByTagName("publicKey").item(0).getNodeValue();
		String signatureAlg = doc1.getElementsByTagName("signatureAlg").item(0).getNodeValue();
		String organizationUnit = doc1.getElementsByTagName("organizationUnit").item(0).getNodeValue();
		int state = 0;
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		int serial = getFreeSerial();
		conn.close();
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");

		certGen.setSerialNumber(new BigInteger(serial + ""));
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(notAfter);
		certGen.setNotAfter(notBefore);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(convStringToPubKey(publicKey));
		certGen.setSignatureAlgorithm(signatureAlg);
		certGen.addExtension("organizzaziotnUnit", false, organizationUnit.getBytes());
		
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
		conn.close();
		
	    String certString = convX509ToBase64(cert);
        
	    conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		insertUsrCert(certString, state, getStringDate(notAfter), getStringDate(notBefore), serial + "", subjectDN);
		conn.close();
		
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc2 = docBuilder.newDocument();
        Element root = doc2.createElement("createNewCertificateSSResp");
        Element certEl = doc2.createElement("serial");
        certEl.appendChild(doc2.createTextNode(serial + ""));
        root.appendChild(certEl);
        Element stateEl = doc2.createElement("cert");
        stateEl.appendChild(doc2.createTextNode(convX509ToBase64(cert)));
        root.appendChild(stateEl);
        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
        sendWithDigest(root);
        conn.close();
	}
	
	//Invia il certificato appena creato sotto richiesta dell'utente
	protected void createNewCertificate(String message) throws TransformerException, IOException, ParserConfigurationException, DOMException, SQLException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, CertificateException, SAXException{
		
		Document doc1 = convStringToXml(message);
		Date notAfter = convStringToDate(doc1.getElementsByTagName("notAfter").item(0).getNodeValue());
		Date notBefore = convStringToDate(doc1.getElementsByTagName("notBefore").item(0).getNodeValue());
		String subjectDN = doc1.getElementsByTagName("subjectDN").item(0).getNodeValue();
		String publicKey = doc1.getElementsByTagName("publicKey").item(0).getNodeValue();
		String signatureAlg = doc1.getElementsByTagName("signatureAlg").item(0).getNodeValue();
		String organizationUnit = doc1.getElementsByTagName("organizationUnit").item(0).getNodeValue();
		int state = 0;
		
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		int serial = getFreeSerial();
		conn.close();
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");

		certGen.setSerialNumber(new BigInteger(serial + ""));
		certGen.setIssuerDN(getCACert().getSubjectX500Principal());
		certGen.setNotBefore(notAfter);
		certGen.setNotAfter(notBefore);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(convStringToPubKey(publicKey));
		certGen.setSignatureAlgorithm(signatureAlg);
		certGen.addExtension("organizzaziotnUnit", false, organizationUnit.getBytes());

		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
		conn.close();
		
	    String certString = convX509ToBase64(cert);
	    
	    conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		insertUsrCert(certString, state, getStringDate(notAfter), getStringDate(notBefore), serial + "", subjectDN);
		conn.close();
		
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc2 = docBuilder.newDocument();
        Element root = doc2.createElement("createNewCertificateSSResp");
        Element certEl = doc2.createElement("serial");
        certEl.appendChild(doc2.createTextNode(serial + ""));
        root.appendChild(certEl);
        Element stateEl = doc2.createElement("cert");
        stateEl.appendChild(doc2.createTextNode(convX509ToBase64(cert)));
        root.appendChild(stateEl);
        
        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
        sendWithDigest(root);
        conn.close();
	       
	}
	
	protected void revokedCert(String message, String cert, int reason) throws TransformerException, IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, SQLException, ParserConfigurationException, InvalidKeyException, SignatureException, SAXException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message));
		conn.close();
		
		if (b == true){
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			setStateCert(cert, REVOKED, 0);
			conn.close();
			
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
			
			crlGen.setIssuerDN(getCACert().getSubjectX500Principal());
			crlGen.setThisUpdate(getDate());
			crlGen.setNextUpdate(getDate());
			crlGen.setSignatureAlgorithm(CRL_SIGN_ALG);
			crlGen.addCRLEntry(new BigInteger(cert), getDate(), CRLReason.privilegeWithdrawn);
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("revokedCertResp");
			conn.close();
		}
		
	}
	
	protected void renewCert(String message, String serialCert, String newNotBefore, String newPublicKey) throws SQLException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, TransformerException, SAXException, IOException, ParserConfigurationException, IllegalArgumentException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message));
		conn.close();
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		ResultSet rs = getUsrCert(serialCert);
		String cert = rs.getString(1);
		X509Certificate vecchio = convBase64ToX509(cert);
		//cert, state, notAfter, notBefore, serialNumber, subjectDN
		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");

		certGen.setSerialNumber(vecchio.getSerialNumber());
		certGen.setIssuerDN(vecchio.getIssuerX500Principal());
		certGen.setNotBefore(vecchio.getNotAfter());
		certGen.setNotAfter(convStringToDate(newNotBefore));
		certGen.setSubjectDN(vecchio.getSubjectX500Principal());                       
		certGen.setPublicKey(convBase64ToPubKey(newPublicKey));
		certGen.setSignatureAlgorithm(vecchio.getSigAlgName());
		certGen.addExtension("organizzaziotnUnit", false, vecchio.getExtensionValue("organizzaziotnUnit"));
		
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		X509Certificate newCert = certGen.generate(getCaPrivKey(), "BC");
		conn.close();
		
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		deleteUsrCert(serialCert);
		conn.close();
		
		String subjectDN = vecchio.getSubjectDN().getName();
		String notAfter = getStringDate(vecchio.getNotAfter());
		String strCert = convX509ToBase64(newCert);
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		insertUsrCert(strCert, 0, notAfter, newNotBefore, serialCert, subjectDN);
		conn.close();
		
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc2 = docBuilder.newDocument();
        Element root = doc2.createElement("renewCertResp");
        Element certEl = doc2.createElement("serial");
        certEl.appendChild(doc2.createTextNode(serialCert + ""));
        root.appendChild(certEl);
        Element stateEl = doc2.createElement("cert");
        stateEl.appendChild(doc2.createTextNode(strCert));
        root.appendChild(stateEl);
        
        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
        sendWithDigest(root);
        conn.close();
		
	}
	
	@SuppressWarnings("deprecation")
	protected void sendCRL() throws ParserConfigurationException, CRLException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, SQLException, TransformerException, IOException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		X509CRL crl = crlGen.generateX509CRL(getCaPrivKey(), "BC");
		conn.close();
		String crlString = convCrlToBase64(crl);
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		//create the root element and add it to the document
		Element root = doc.createElement("message");
		root.setAttribute("operation", "sendCRLResp");
		Element response = doc.createElement("crl");
		response.appendChild(doc.createTextNode(crlString));
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		sendWithDigest(root);
		conn.close();
	}
	
	//Inserisce un nuovo utente
	protected void insertNewUser(String user) throws ParserConfigurationException, SQLException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, TransformerException, IOException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = insertUser(user);
		conn.close();
		System.out.println(user + " inserito " + b);
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		//create the root element and add it to the document
		Element root = doc.createElement("message");
		root.setAttribute("operation", "insertUserResp");
		Element response = doc.createElement("result");
		response.appendChild(doc.createTextNode("true"));
		root.appendChild(response);
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		sendWithDigest(root);
		conn.close();
	}
	
	//Invia la chiave pubblica della CA
	protected void sendCaPubKey() throws DOMException, InvalidKeySpecException, NoSuchAlgorithmException, SQLException, ParserConfigurationException, TransformerException, IOException{
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		//create the root element and add it to the document
		Element root = doc.createElement("message");
		root.setAttribute("operation", "sendCaPubKeyResp");
		Element response = doc.createElement("caPublicKey");
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		response.appendChild(doc.createTextNode(convPubKeyToBase64(getCaPubKey())));
		conn.close();
		System.out.println("Ho esptratto la chiave");
		root.appendChild(response);
		sendWithoutDigest(root);
	}
	
	//Controlla se un utente è presente
	protected void checkUsr(String user) throws ParserConfigurationException, SQLException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, TransformerException, IOException{
		System.out.println("Tento la query");
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean result = searchUsr(user);
		conn.close();
		System.out.println("Ho fatto la query");
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		Document doc = docBuilder.newDocument();
		//create the root element and add it to the document
		Element root = doc.createElement("message");
		root.setAttribute("operation", "checkUsrResp");
		Element response = doc.createElement("result");
		response.appendChild(doc.createTextNode(result + ""));
		root.appendChild(response);
		
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		sendWithDigest(root);
		conn.close();
	}
	
	//Metodi per le operazioni

	
	//Crea un certificato
	protected X509Certificate createCert(Date startDate, Date expiryDate, BigInteger serialNumber, KeyPair keyPair, String signatureAlgorithm, X509Certificate caCert, PrivateKey caKey) throws CertificateParsingException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException{
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
	
	//Restituisce la data attuale nel formato Date
	@SuppressWarnings("deprecation")
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
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws SQLException 
	 
	 */
	
	//Restituisce la chiave privata della CA
	protected PrivateKey getCaPrivKey() throws InvalidKeySpecException, NoSuchAlgorithmException, SQLException{
		ResultSet rs = getCAKeyFromDB();
		rs.next();
		String base64Key = rs.getString(1);
		System.out.println("la chiave leta dal bd è " + base64Key);
		PrivateKey key = convBase64ToPrivKey(base64Key);
		return key;
	}
	
	//Restituisce la chiave pubblica della CA
	protected PublicKey getCaPubKey() throws InvalidKeySpecException, NoSuchAlgorithmException, SQLException{
		ResultSet rs = getCAKeyFromDB();
		rs.next();
		System.out.println("Fatto1");
		String base64Key = rs.getString(2);
		System.out.println("Fatto2");
		PublicKey key = convBase64ToPubKey(base64Key);
		return key;
	}
	
	//Restituisce il certificato della CA
	protected X509Certificate getCACert() throws CertificateException, NoSuchProviderException, SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		ResultSet rs = getCAKeyFromDB();
		rs.next();
		String cert = rs.getString(3);
		return convBase64ToX509(cert);
	}
	
	//Restituisce il primo seriale disponibile
	protected int getSerial(){
		return lastSerial;
	}
	
	//Incrementa il numero seriale usato per i nuovi certificati
	protected void incSerial() throws SQLException{
		getSerial();
		lastSerial += 1;
	}
	
	//Blocca il seriale disponibile
	protected int getFreeSerial() throws SQLException{
		int serial = getSerial() + 1;
		incSerial();
		return serial;
	}
	
	
	//Metodi per i messaggi XML
	
	//Genera la firma base64 di un messaggio
	protected String createDigest(String data, PrivateKey kpriv) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException{
		Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
		s.initSign(kpriv);
		s.update(data.getBytes());
		byte[] signature = s.sign();
		return new String(Base64.encode(signature));
	}
	
	//Controlla la firma di un messaggio
	protected boolean checkDigest(Document doc) throws SignatureException, InvalidKeyException, CertificateException, NoSuchProviderException, SQLException, NoSuchAlgorithmException, TransformerException{
		String message = getMessage(doc);
		String digest64 = getDigest64(doc);
		String sender = getSender(doc);
		Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
		s.update(message.getBytes());
		boolean digestOK = false;
		ResultSet certificates = getValidUserCert(sender);
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
	}
	
	//Restituisce la stringa rappresentante il messaggio
	protected String getMessage(Document doc) throws TransformerException{
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
	}
	
	//Restituisce la stringa BASE64 rappresentante la firma
	protected String getDigest64(Document doc) throws TransformerException{
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
	}
	
	//Restituisce la stringa rappresentante il mittente del messaggio
	protected String getSender(Document doc){
		//doc.getDocumentElement().normalize();
		NamedNodeMap attrs = (doc.getElementsByTagName("document").item(0)).getAttributes();
		Node senderNode = attrs.getNamedItem ("sender");
		String sender = senderNode.getNodeValue();
		return sender;
	}
	
	//Metodi per le conversioni varie
	
	//Converte unsa Stringa in formato gg/mm/aaaa in util.Date
	@SuppressWarnings("deprecation")
	protected Date convStringToDate(String s){
		StringTokenizer token = new StringTokenizer(s, "/");
		int day = Integer.parseInt(token.nextToken());
		int month = Integer.parseInt(token.nextToken());
		int year = Integer.parseInt(token.nextToken());
		return new Date (year, month, day);
	}
	
	
	
	//Converte un Date in formato gg/mm/aaaa
	@SuppressWarnings("deprecation")
	protected String getStringDate(Date date){
		String year = ("0" + date.getYear());
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + date.getMonth());
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + date.getDay());
		day = day.substring(day.length() - 2, day.length());
		return day + "/" + month + "/" + year;
	}
	
	//Restituisce la data attuale nel formato gg/mm/aaaa
	protected static String getStringDate(){
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
		return year + "/" + month + "/" + day;
	}
	
	//Converte una stringa in una chiave pubblica
	protected static PublicKey convStringToPubKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] publicKeyBytes = publicKey.getBytes();
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}
	
	//Converte una stringa in una chiave privata
	protected static PrivateKey convStringToPrivKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] privateKeyBytes = privateKey.getBytes();
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(ks);
	}
	
	//Converte una stringa BASE64 in una chiave pubblica
	protected static PublicKey convBase64ToPubKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] publicKeyBytes =  Base64.decode(publicKey);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}
	/**
	//Converte una stringa BASE64 in una chiave privata
	protected static PrivateKey convBase64ToPrivKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] privateKeyBytes = Base64.decode(privateKey);
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(ks);
	}*/
	//Converte una stringa Base64 in una chiave privata
	public static PrivateKey convBase64ToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		System.out.println("La chiave che vohgli: " + privateKey);
		byte[] privateKeyBytes = privateKey.getBytes();
		byte[] conv = Base64.decode(privateKeyBytes);
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(conv);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
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
	protected Document convStringToXml(String s) throws SAXException, IOException, ParserConfigurationException{
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
	protected String convX509ToXML (X509Certificate certSigned) throws TransformerException, ParserConfigurationException, CertificateEncodingException{
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
	
	//Converte un X509CRL in Base64
	protected String convCrlToBase64(X509CRL crl) throws CRLException{
		byte[] crlByte = crl.getEncoded();
		byte[] clrBase64 = Base64.encode(crlByte);
		return new String(clrBase64);
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
	
	//Query con insert
	
	//Imposta l'ultimo seriale usato nella tabella del BD
	protected void setSerialInDB(int newSerial) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSerial;");
		if (rs.next()){
			stm.executeUpdate("UPDATE tblSeriale SET serial = " + newSerial + ";");
		}else{
			stm.executeUpdate("INSERT INTO tblSeriale VALUES (2);");
		}
	}
	
	//Inserisce un nuovo record nei certifiati della CA
	protected void insertCACert(String serial, String privKey, String pubKey, String cert) throws SQLException{
		Connection conn1 = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	    Statement stm = conn1.createStatement();
		stm.executeUpdate("INSERT INTO tblCACert (serialNumber, privateKey, publicKey, cert) VALUES ('" + serial + "', '" + privKey + "', '" + pubKey + "', '" + cert + "');");
		stm.close();
		conn1.close();
	}
	
	//Inserisce un nuovo certificato tra quelli degli utenti
	protected void insertUsrCert(String cert, int state, String notAfter, String notBefore, String serialNumber, String subjectDN) throws SQLException{
	    //Statement stm = conn1.createStatement();
		PreparedStatement ps = conn.prepareStatement( "INSERT INTO tblUsrCert (cert, state, notAfter, notBefore, serialNumber, subjectDN)" +
				                                    "VALUES ?, ?, ?, ?, ?, ?;");
		ps.setString(1, cert);
		ps.setInt(2, state);
		ps.setString(3, notAfter);
		ps.setString(4, notBefore);
		ps.setString(5, serialNumber);
		ps.setString(6, subjectDN);
		ps.executeUpdate();	
		//incSerial();
		ps.close();
	}
	
	//Aggiorna la scadenza di un certificato
	protected void renewalCert(String serial, String newNotBefore) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet result;
		result = stm.executeQuery("SELECT notBefore FROM tblRinnovi WHERE serialNumeber = '" + serial + "';");
		result.next();
		String oldNotBefore = result.getString(0);
		
		Connection conn1 = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	    Statement stm1 = conn.createStatement();
		stm1.executeQuery("UPDATE userCertificate SET notBefore = '" + newNotBefore + " WHERE serialNumber = " + serial + "';");
		stm1.executeQuery("INSERT INTO  tblRinnovi (data, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getStringDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "';");
		stm1.close();
		conn1.close();
	}
	
	//Inserisce un nuovo utente nel DB
	protected boolean insertUser(String subjectDN) throws SQLException{
		if (!userAlreadyExist(subjectDN)){
		    Statement stm = conn.createStatement();
			stm.executeUpdate("INSERT INTO tblUsers VALUES ('" + subjectDN + "');");
			System.out.println("-----------------------");
			return true;
		}else{
			return false;
		}	
	}
	
	//Query senza insert
	
	//Ottiene l'ultimo seriale usato dalla tabella del DB
	protected void getSerialToDB() throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSeriale");
		if (rs.next()){
			lastSerial = rs.getInt("serial");
		}else{
			lastSerial = 1;
		}
	}
	
	//Controlla se il seriale è già usato nel DB
	@SuppressWarnings("unused")
	private boolean serialAlreadyExist(String serialNumber) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsrCert WHERE serialNumber = '" + serialNumber + "';");
		return rs.next();
	}
	
	//Controlla se il subjectDN è già usato nel DB
	private boolean userAlreadyExist(String subjectDN) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsers WHERE subjectDN = '" + subjectDN + "';");
		return rs.next();
	}
	
	//Restituisce la lista degli utenti della CA
	protected ResultSet getCAUser() throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT subjecDN from tblUsers;" );
	}
	
	//Restituisce tutti i certificati validi di un utente
	protected ResultSet getValidUserCert(String user) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE state = 'good' AND issuerDN = '" + user + "';" );
	}
	
	//Restituisce tutti i certificati di un utente
	protected ResultSet getAllUserCert(String user) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE issuerDN = '" + user + "';" );
	}
	
	//Cerca un utente
	protected boolean searchUsr(String usr) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsers WHERE subjectDN = '" + usr + "';");
		return rs.next();
	}
	
	//Restituisce i certificati della CA
	protected ResultSet getCAKeyFromDB() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT privateKey, publicKey, cert FROM tblCACert;");	
	}	
	
	//Restituisce un certificato
	protected ResultSet getUsrCert(String serial) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN WHERE serial = '" + serial +"';");
	}
	
	//Restituisce il certificato della CA
	protected ResultSet getCACert(String serial) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert FROM tblCACert;");	
	}
	
	//Restituisce la lista dei certificati revocati
	protected ResultSet getRevokedCert() throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT serialNumber FROM tblUsrCert WHERE state = '" + REVOKED + "';");
	}
	
	//Setta lo stato di un certificato
	protected void setStateCert(String serial, String state, int reason) throws SQLException{
	    Statement stm = conn.createStatement();
		stm.executeUpdate("UPDATE tblUsrCert SET state = '"+ state +"' AND reason = '" + reason + "' WHERE serialNumber = " + serial + "';");
	}
	
	//Restituisce lo stato di un certificato
	protected String getCertState(String serial) throws SQLException {
	    Statement stm = conn.createStatement();
		ResultSet result = (stm.executeQuery("SELECT state FROM tblUsrCert WHERE serialNumber = '" + serial + ",;"));
		result.next();
		conn.commit();
		stm.close();
		return result.getString(0);
	}
	
	//Elimina un certificato
	protected void deleteUsrCert(String serial) throws SQLException{
		Statement stm = conn.createStatement();
		stm.executeQuery("DELETE FROM tblUsrCert WHERE serialNumber = '" + serial + ",;");
		stm.close();
	}
	
	
	
	/**
	//Inserisce un nuovo utente, da ricontrollare per uniformarlo al DB
	protected void insertUser(String commonName, String organization, String email, String organizationUnit, String locality, String state, String country) throws SQLException{
		stm.executeQuery("INSERT INTO user (user.commonName, user.organization, user.email, user.organizationUnit, user.locality, user.state, user.country) VALUES ('" + commonName + "','" + organization + "','" + organizationUnit + "','" + locality + "','" + state + "','" + country + "');");
		
	}
	*/
	/**
	//Restituisce la data attuale nel forato AAAA/M/GG HH:MM:SS
	private static String getDate(){
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
	}*/
	
	/**
	//Inserisce un nuovo record nei certifiati della CA
	protected void insertCACert(String issuerDN, String notAfter, String notBefore, String privateKey, String publicKey, String signatureAlgorithm, String subjectDN, String state) throws SQLException{
		String serialNumber = getSerial() + "";
		PreparedStatement ps=conn.prepareStatement( "INSERT INTO tblCACert (issuerDN, notAfter, notBefore, privateKey, publicKey, serialNumber, signatureAlgorithm, subjectDN, state)" +
				                                    "VALUES ?, ?, ?, ?, ?, ?, ?, ?, ?;");
		ps.setString(1, issuerDN);
		ps.setString(2, notAfter);
		ps.setString(3, notBefore);
		ps.setString(4, privateKey);
		ps.setString(5, publicKey);
		ps.setString(6, serialNumber);
		ps.setString(7, signatureAlgorithm);
		ps.setString(8, subjectDN);
		ps.setString(9, state);
		ps.executeUpdate();	
		incSerial();
	}*/
	
	
	
}
