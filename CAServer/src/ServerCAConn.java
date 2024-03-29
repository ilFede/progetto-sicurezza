// Fare in modo che sia il gestore delle operazioni a gestire le eccezioni, mandando in caso negativo un messaggio di errore standared firmato

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
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
import java.security.Security;
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
	//protected X509V2CRLGenerator crlGen;
	protected final String DIGEST_SIGN_ALG = "MD2withRSA";
	protected final String GOOD = "good";
	protected final String REVOKED = "revoked";
	protected final String EXPIRED = "expired";
	protected final String CANAME = "CN=Test CA Certificate";
	protected final String CRL_SIGN_ALG = "MD2withRSA";
	protected final String OP_FAIL = "fail";
	protected final String organizationOID = X509Extensions.IssuerAlternativeName.toString();
	protected final String CA_NAME = "CN=Test CA Certificate";
	//private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
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
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider ());
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
		//this.crlGen = crlGen;
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
		root.setAttribute("success", false + "");
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
					
				}else if (opName.equals("sendCertUsrList")){
					String usr = messNode.getChildNodes().item(0).getChildNodes().item(0).getNodeValue();
					sendCertUsrList(message, usr);
					
				}else if (opName.equals("sendRenewableUsrCert")){
					System.out.println("Etrto");
					String usr = doc.getElementsByTagName("user").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("L'utente è: ");
					sendRenewableUsrCert(message, usr);
					
				}else if (opName.equals("sendValidUsrCert")){
					System.out.println("Etrto");
					String usr = doc.getElementsByTagName("user").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("L'utente è: ");
					sendValidUsrCert(message, usr);
					
				}else if (opName.equals("sendUsrCert")){
					System.out.println("Etrto");
					String usr = doc.getElementsByTagName("user").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("L'utente è: ");
					sendCertUsrList(message, usr);
					
				}else if (opName.equals("sendOcsp")){
					String serial = doc.getElementsByTagName("serial").item(0).getChildNodes().item(0).getNodeValue();
					sendOcsp(message, serial);
					
				}else if (opName.equals("createNewCertificateSS")){
					createNewCertificateSS(message);
					
				}else if (opName.equals("createNewCertificate")){
					String serial = doc.getElementsByTagName("serialSign").item(0).getChildNodes().item(0).getNodeValue();
					createNewCertificate(message, serial);
					
				}else if (opName.equals("revokeCert")){
					String serial = doc.getElementsByTagName("serial").item(0).getChildNodes().item(0).getNodeValue();
					String reason = doc.getElementsByTagName("reason").item(0).getChildNodes().item(0).getNodeValue();
					String serialSign = doc.getElementsByTagName("serialSign").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("Entrato" + serial + " " + reason + " " + serialSign);
 
					revokedCert(message, serial, Integer.parseInt(reason), serialSign);
					
				}else if (opName.equals("renewsCertificate")){
					
					String cert = doc.getElementsByTagName("serial").item(0).getChildNodes().item(0).getNodeValue();
					String newNotBefore = doc.getElementsByTagName("newNotBefore").item(0).getChildNodes().item(0).getNodeValue();
					String publicKey = doc.getElementsByTagName("publicKey").item(0).getChildNodes().item(0).getNodeValue();
					String signatureSerial = doc.getElementsByTagName("serialSign").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("Entrato" + cert + " " + newNotBefore + " " + publicKey + " " + signatureSerial);
					renewCert(message, cert, newNotBefore, publicKey, signatureSerial);
					
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
		//boolean b = checkDigest(convStringToXml(message));
		boolean b = true;
		conn.close();
		if (b == true){
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc = docBuilder.newDocument();
	        //create the root element and add it to the document
	        Element root = doc.createElement("message");
	        root.setAttribute("operation", "sendUsrListResp");
	        root.setAttribute("success", "true");
			System.out.println("provo i risultati");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getCAUser();
			System.out.println("Ho i risultati");
			while (rs.next()){
				System.out.println("Ho un buono!");
				String serial = rs.getString(1);
				System.out.println(serial);
				Element usr = doc.createElement("user");
				usr.appendChild(doc.createTextNode(serial));
				root.appendChild(usr);
			}
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
	
	//Invia la lista dei certificati di un utente
	protected void sendCertUsrList(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
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
	        root.setAttribute("operation", "sendCertUsrListResp");
	        boolean success = false;
			System.out.println("provo i risultati");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getListUserCert(user);
			System.out.println("Ho i risultati");
			while (rs.next()){
				success = true;
				System.out.println("Ho un buono!");
				String serial = rs.getString(5);
				System.out.println(serial);
				Date notBefore = convStringToDate(rs.getString(4));
				System.out.println(notBefore);
				System.out.println(convDateToString(notBefore));
				Date now = getDate();
				System.out.println(convDateToString(now));
				Element usr = doc.createElement("cert");
				usr.appendChild(doc.createTextNode(serial));
				root.appendChild(usr);
			}
			conn.close();
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	        root.setAttribute("success", success + "");
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendHaveValidCertResp");
			conn.close();
		}	
	}
	
	//Invia la lista dei certificati validi di un utente
	protected void sendValidUsrCert(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
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
	        root.setAttribute("operation", "sendValidUsrCertResp");
	        boolean success = false;
	        root.setAttribute("success", "true");
			System.out.println("provo i risultati");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getValidUserCert(user);
			System.out.println("Ho i risultati");
			while (rs.next()){
				success = true;
				System.out.println("Ho un buono!");
				String serial = rs.getString(5);
				System.out.println(serial);
				Date notBefore = convStringToDate(rs.getString(4));
				System.out.println(notBefore);
				System.out.println(convDateToString(notBefore));
				Date now = getDate();
				System.out.println(convDateToString(now));
				if (now.compareTo(notBefore) <= 0){
					Element usr = doc.createElement("cert");
					usr.appendChild(doc.createTextNode(serial));
					root.appendChild(usr);
				}
			}
			conn.close();
	        root.setAttribute("success", success + "");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendHaveValidCertResp");
			conn.close();
		}	
	}
	
	//Invia la lista dei certificati rinnovabili di un utente
	protected void sendRenewableUsrCert(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
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
	        root.setAttribute("operation", "sendRenewableUsrCertResp");
	        boolean success = false;
	        root.setAttribute("success", "true");
			System.out.println("provo i risultati");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getValidUserCert(user);
			System.out.println("Ho i risultati");
			while (rs.next()){
				success = true;
				System.out.println("Ho un buono!");
				String serial = rs.getString(5);
				System.out.println(serial);
				Date notBefore = convStringToDate(rs.getString(4));
				System.out.println(notBefore);
				System.out.println(convDateToString(notBefore));
				Date now = getDate();
				System.out.println(convDateToString(now));
				Element usr = doc.createElement("cert");
				usr.appendChild(doc.createTextNode(serial));
				root.appendChild(usr);
			}
			conn.close();
	        root.setAttribute("success", success + "");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendHaveValidCertResp");
			conn.close();
		}	
	}
	/**
	//Invia la lista dei certificati di un utente
	protected void sendUsrCert(String message, String user) throws SAXException, IOException, ParserConfigurationException, SQLException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
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
	        boolean success = false;
	        System.out.println("provo i risultati");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getListUserCert(user);
			System.out.println("Ho i risultati");
			while (rs.next()){
				success = true;
				System.out.println("Ho un buono!");
				String serial = rs.getString(5);
				System.out.println(serial);
				Date notBefore = convStringToDate(rs.getString(4));
				System.out.println(notBefore);
				System.out.println(convDateToString(notBefore));
				Date now = getDate();
				System.out.println(convDateToString(now));
				if (now.compareTo(notBefore) <= 0){
					Element usr = doc.createElement("cert");
					usr.appendChild(doc.createTextNode(serial));
					root.appendChild(usr);
				}
			}
	        root.setAttribute("success", success + "");
			conn.close();
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("sendHaveValidCertResp");
			conn.close();
		}	
	}*/
	//Invia i dettagli di un certificato da usare come OCSP
	protected void sendOcsp(String message, String serialCert) throws SQLException, ParserConfigurationException, SAXException, IOException, TransformerException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = true;
		//boolean b = checkDigest(convStringToXml(message));
		conn.close();
		if (b == true){
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getUserCert(serialCert);
			System.out.println("Ho fatto laquery!!!!!!!!");
			rs.next();
			System.out.println("Ho fatto laquery!!!!!!!!");
			System.out.println(serialCert);
			String cert = rs.getString(1);
			String state = rs.getString(2);
			String notBefore = rs.getString(3);
			String notAfter = rs.getString(4);
			String serialNumber = rs.getString(5);
			String subjectDN = rs.getString(6);
			String reason = rs.getString(7);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            //create the root element and add it to the document
            Element root = doc.createElement("message");
            root.setAttribute("operation", "sendOcspResp");
	        root.setAttribute("success", "true");
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
            Element reasonEl = doc.createElement("reason");
            reasonEl.appendChild(doc.createTextNode(reason));
            root.appendChild(reasonEl);
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
		System.out.println("Inizio a leggere i dati per il nuovo certidicato\n" + message);
		Document doc1 = convStringToXml(message);
		System.out.println("Ho convertito il messaggio");

		Date notAfter = convStringToDate(doc1.getElementsByTagName("notAfter").item(0).getChildNodes().item(0).getNodeValue());
		System.out.println("Not afret: " + notAfter);
		Date notBefore = convStringToDate(doc1.getElementsByTagName("notBefore").item(0).getChildNodes().item(0).getNodeValue());
		System.out.println("Not afret: " + notAfter);
		String subjectDN = doc1.getElementsByTagName("subjectDN").item(0).getChildNodes().item(0).getNodeValue();
		System.out.println("Not afret: " + notAfter);
		String publicKey = doc1.getElementsByTagName("publicKey").item(0).getChildNodes().item(0).getNodeValue();
		String signatureAlg = doc1.getElementsByTagName("signatureAlg").item(0).getChildNodes().item(0).getNodeValue();
		String organizationUnit = doc1.getElementsByTagName("organizationUnit").item(0).getChildNodes().item(0).getNodeValue();
		System.out.println("Provo a farmi dare un seriale");
		String state = GOOD;
		//conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		int serial = getFreeSerial();
		//conn.close();
		System.out.println("Mi sono fatto dare un seriale");
		System.out.println("La chive pub arrivata è: " + publicKey);

		
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal(CA_NAME);
		X500Principal dnSubject = new X500Principal(subjectDN);

		certGen.setSerialNumber(new BigInteger(serial + ""));
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(notAfter);
		certGen.setNotAfter(notBefore);
		certGen.setSubjectDN(dnSubject);  
		System.out.println("provo a convertire la chiace");
		certGen.setPublicKey(convBase64ToPubKey(publicKey));
		System.out.println("Messa dentro");
		certGen.setSignatureAlgorithm(signatureAlg);
		certGen.addExtension(organizationOID, false, organizationUnit.getBytes());
		
		System.out.println("Provo a farmi dare la chiave privata dala CA");

		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
		conn.close();
		
	    String certString = convX509ToBase64(cert);
        
	    conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		insertUsrCert(certString, state, convDateToString(notAfter), convDateToString(notBefore), serial + "", subjectDN, "0");
		conn.close();
		
		DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
        Document doc2 = docBuilder.newDocument();
        Element root = doc2.createElement("message");
        root.setAttribute("success", "true");
        root.setAttribute("operation", "createNewCertificateSSResp");
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
	
	//Invia il certificato dopo la richiesta di uno firmato
	protected void createNewCertificate(String message, String signatureSerial) throws SAXException, IOException, ParserConfigurationException, SQLException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, TransformerException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message), signatureSerial);
		conn.close();
		if (b == true){
			System.out.println("Inizio a leggere i dati per il nuovo certidicato\n" + message);
			Document doc1 = convStringToXml(message);
			System.out.println("Ho convertito il messaggio");
	
			Date notAfter = convStringToDate(doc1.getElementsByTagName("notAfter").item(0).getChildNodes().item(0).getNodeValue());
			System.out.println("Not afret: " + notAfter);
			Date notBefore = convStringToDate(doc1.getElementsByTagName("notBefore").item(0).getChildNodes().item(0).getNodeValue());
			System.out.println("Not afret: " + notAfter);
			String subjectDN = doc1.getElementsByTagName("subjectDN").item(0).getChildNodes().item(0).getNodeValue();
			System.out.println("Not afret: " + notAfter);
			String publicKey = doc1.getElementsByTagName("publicKey").item(0).getChildNodes().item(0).getNodeValue();
			String signatureAlg = doc1.getElementsByTagName("signatureAlg").item(0).getChildNodes().item(0).getNodeValue();
			String organizationUnit = doc1.getElementsByTagName("organizationUnit").item(0).getChildNodes().item(0).getNodeValue();
			System.out.println("Provo a farmi dare un seriale");
			//int state = 0;
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			int serial = getFreeSerial();
			conn.close();
			System.out.println("Mi sono fatto dare un seriale");
			System.out.println("La chive pub arrivata è: " + publicKey);
	
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal dnName = new X500Principal(CA_NAME);
			X500Principal dnSubject = new X500Principal(subjectDN);

	
			certGen.setSerialNumber(new BigInteger(serial + ""));
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(notAfter);
			certGen.setNotAfter(notBefore);
			certGen.setSubjectDN(dnSubject);  
			System.out.println("provo a convertire la chiace");
			certGen.setPublicKey(convBase64ToPubKey(publicKey));
			System.out.println("Messa dentro");
			certGen.setSignatureAlgorithm(signatureAlg);
			certGen.addExtension(organizationOID, false, organizationUnit.getBytes());
			
			System.out.println("Provo a farmi dare la chiave privata dala CA");
	
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			X509Certificate cert = certGen.generate(getCaPrivKey(), "BC");
			conn.close();
			
		    String certString = convX509ToBase64(cert);
	        
		    conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			insertUsrCert(certString, GOOD, convDateToString(notAfter), convDateToString(notBefore), serial + "", subjectDN, "0");
			conn.close();
			
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc2 = docBuilder.newDocument();
	        Element root = doc2.createElement("message");
	        root.setAttribute("operation", "createNewCertificateSSResp");
	        root.setAttribute("success", "true");
	        Element certEl = doc2.createElement("serial");
	        certEl.appendChild(doc2.createTextNode(serial + ""));
	        root.appendChild(certEl);
	        Element stateEl = doc2.createElement("cert");
	        stateEl.appendChild(doc2.createTextNode(convX509ToBase64(cert)));
	        root.appendChild(stateEl);
	        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	        sendWithDigest(root);
	        conn.close();
		}else{
			sendFailure("createNewCertificateResp");
		}
	}
	
	/**
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
		certGen.setPublicKey(convBase64ToPubKey(publicKey));
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
	       
	}*/
	
	protected void revokedCert(String message, String cert, int reason, String serial) throws TransformerException, IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, SQLException, ParserConfigurationException, InvalidKeyException, SignatureException, SAXException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message), serial);
		conn.close();
		
		if (b == true){
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			System.out.println("Fatto1");
			setStateCert(cert, REVOKED, reason);
			conn.close();
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			System.out.println("Fatto2");
			insertRevokedCert(cert, reason);
			conn.close();
			System.out.println("Fatto3");

			//crlGen.addCRLEntry(new BigInteger(cert), getDate(), reason);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "revokedCertResp");
	        root.setAttribute("success", "true");
			Element response = doc.createElement("result");
			response.appendChild(doc.createTextNode("OK"));
			root.appendChild(response);
			/**
			crlGen.setIssuerDN(getCACert().getSubjectX500Principal());
			crlGen.setThisUpdate(getDate());
			crlGen.setNextUpdate(getDate());
			crlGen.setSignatureAlgorithm(CRL_SIGN_ALG);
			crlGen.addCRLEntry(new BigInteger(cert), getDate(), CRLReason.privilegeWithdrawn);
			*/
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendWithDigest(root);
			conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("revokedCertResp");
			conn.close();
		}
		
	}
	
	protected void renewCert(String message, String serialCert, String newNotBefore, String newPublicKey, String signatureSerial) throws SQLException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, TransformerException, SAXException, IOException, ParserConfigurationException, IllegalArgumentException, InvalidKeySpecException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		boolean b = checkDigest(convStringToXml(message), signatureSerial);
		conn.close();
		if (b == true){
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			ResultSet rs = getUserCert(serialCert);
			String cert = rs.getString(1);
			X509Certificate vecchio = convBase64ToX509(cert);
			//cert, state, notAfter, notBefore, serialNumber, subjectDN
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			//X500Principal dnName = new X500Principal("CN=Test CA Certificate");
	
			certGen.setSerialNumber(vecchio.getSerialNumber());
			certGen.setIssuerDN(vecchio.getIssuerX500Principal());
			certGen.setNotBefore(vecchio.getNotBefore());
			certGen.setNotAfter(convStringToDate(newNotBefore));
			certGen.setSubjectDN(vecchio.getSubjectX500Principal());                       
			certGen.setPublicKey(convBase64ToPubKey(newPublicKey));
			certGen.setSignatureAlgorithm(vecchio.getSigAlgName());
			certGen.addExtension(organizationOID, false, vecchio.getExtensionValue(organizationOID));
			conn.close();
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			X509Certificate newCert = certGen.generate(getCaPrivKey(), "BC");
			conn.close();
			
			System.out.println("fatto");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			deleteUsrCert(serialCert);
			conn.close();
			
			System.out.println("fatto2");
			
			String subjectDN = vecchio.getSubjectDN().getName();
			String notAfter = convDateToString(vecchio.getNotAfter());
			String strCert = convX509ToBase64(newCert);
			
			System.out.println("fatto3"); 
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			insertUsrCert(strCert, "good", notAfter, newNotBefore, serialCert, subjectDN, "0");
			conn.close();
			/**
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			insertUsrCert(strCert, "GOOD", notAfter, newNotBefore, serialCert, subjectDN, "0");
			conn.close();
			*/
			String oldNotBefore = convDateToString(vecchio.getNotBefore());
			
			System.out.println("fatto4");
			
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			insertRinnCert(serialCert, newNotBefore, oldNotBefore);
			conn.close();
			
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc2 = docBuilder.newDocument();
	        Element root = doc2.createElement("message");
	        root.setAttribute("operation", "renewCertResp");
	        root.setAttribute("success", "true");
	        Element certEl = doc2.createElement("serial");
	        certEl.appendChild(doc2.createTextNode(serialCert + ""));
	        root.appendChild(certEl);
	        Element stateEl = doc2.createElement("cert");
	        stateEl.appendChild(doc2.createTextNode(strCert));
	        root.appendChild(stateEl);
	        
	        conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	        sendWithDigest(root);
	        conn.close();
		}else{
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
			sendFailure("revokedCertResp");
			conn.close();
		}
		
	}
	
	@SuppressWarnings("deprecation")
	protected void sendCRL() throws ParserConfigurationException, CRLException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, InvalidKeySpecException, NoSuchAlgorithmException, SQLException, TransformerException, IOException{
		X509V2CRLGenerator   crlGen = new X509V2CRLGenerator();
		crlGen.setIssuerDN(new X500Principal("CN=Test CA"));
		Date now = getDate();
		crlGen.setThisUpdate(now);
		crlGen.setNextUpdate(now);
		crlGen.setSignatureAlgorithm(CRL_SIGN_ALG);
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		ResultSet rs = getRevokedCert();
		while(rs.next()){
			String serial = rs.getString(1);
			BigInteger bigSerial = new BigInteger(serial);
			int reason = rs.getInt(2);
			String strDate = rs.getString(3);
			Date date = convStringToDate(strDate);
			crlGen.addCRLEntry(bigSerial, date, reason);
		}
				
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
		root.setAttribute("success", "true");
		Element response = doc.createElement("crl");
		response.appendChild(doc.createTextNode(crlString));
		root.appendChild(response);
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
	protected Date getDate(){
		GregorianCalendar gc = new GregorianCalendar();
		String year = ("0" + gc.get(Calendar.YEAR));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + gc.get(Calendar.MONTH + 1));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + gc.get(Calendar.DAY_OF_MONTH));
		day = day.substring(day.length() - 2, day.length());
		System.out.println("Data del calendario " + day + month+ year);
		Date date = new Date(Integer.parseInt(year) - 1900, Integer.parseInt(month) - 1, Integer.parseInt(day));
		System.out.println("Date: " + date);
		String s = convDateToString(date);
		System.out.println("Date: " + s);
		System.out.println("Date: " + convStringToDate(s));
		return date;
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
	/**protected int getSerial(){
		return lastSerial;
	}
	
	//Incrementa il numero seriale usato per i nuovi certificati
	protected void incSerial() throws SQLException{
		getSerial();
		lastSerial += 1;
	}*/
	
	//Blocca il seriale disponibile
	protected int getFreeSerial() throws SQLException{
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		int serial = getSerialToDB();
		conn.close();
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		setSerialInDB(serial + 1);
		conn.close();
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
	protected boolean checkDigest(Document doc, String serial) throws SignatureException, InvalidKeyException, CertificateException, NoSuchProviderException, SQLException, NoSuchAlgorithmException, TransformerException{
		String message = getMessage(doc);
		String digest64 = getDigest64(doc);
		Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
		String cert64 = getUserCert(serial).getString(1);
		System.out.println("Ho ricevuto il certificato");
		X509Certificate certif = convBase64ToX509(cert64);
		System.out.println("Ho convertito il certificato");
		PublicKey kpub = certif.getPublicKey();
		System.out.println("Ho estretto la chiva");

		
		s.initVerify(kpub);
		s.update(message.getBytes());
		/**ResultSet certificates = getValidUserCert(sender);
		int col = 0;
		while(certificates.next()){
			col ++;
			PublicKey kpub = convBase64ToX509(certificates.getString(col)).getPublicKey();
			s.initVerify(kpub);
			s.update(message.getBytes());
		    if (s.verify(Base64.decode(digest64))){
		    	digestOK = true;
		    }
		}*/
		return s.verify(Base64.decode(digest64));
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
		int month = Integer.parseInt(token.nextToken()) - 1;
		int year = Integer.parseInt(token.nextToken()) - 1900;
		return new Date (year, month, day);
	}
	
	
	
	//Converte un Date in formato gg/mm/aaaa
	@SuppressWarnings("deprecation")
	protected String convDateToString(Date date){
		String year = ("0" + (date.getYear() + 1900));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + (date.getMonth() + 1));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + date.getDate());
		day = day.substring(day.length() - 2, day.length());
		return day + "/" + month + "/" + year;
	}
	
	//Restituisce la data attuale nel formato gg/mm/aaaa
	protected static String getNowStringDate(){
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
		return day + "/" + month + "/" + year;
	}
	
	/**
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
	}*/
	
	//Converte una stringa Base64 in una chiave pubblica
	public static PublicKey convBase64ToPubKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] publicKeyBytes = publicKey.getBytes();
		byte[] conv = Base64.decode(publicKeyBytes);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(conv);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
	}
	
	//Converte una stringa Base64 in una chiave privata
	public static PrivateKey convBase64ToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] privateKeyBytes = privateKey.getBytes();
		byte[] conv = Base64.decode(privateKeyBytes);
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(conv);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
	}
	
	/**
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
	/**
	//Converte una stringa Base64 in una chiave privata
	public static PrivateKey convBase64ToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		System.out.println("La chiave che vohgli: " + privateKey);
		byte[] privateKeyBytes = privateKey.getBytes();
		byte[] conv = Base64.decode(privateKeyBytes);
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(conv);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
	}*/
	
	/**
	//converte una chiave privata in una stringa
	protected static String convPrivKeyToString(PrivateKey key){
		return new String(Base64.encode(key.getEncoded()));
	}
	
	//converte una chiave pubblica in una stringa
	protected static String convPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}*/
	
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
        n = xmldoc.createTextNode(convPubKeyToBase64(certSigned.getPublicKey()));
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
		//String strCert = new String(cert.getEncoded());
		byte[] byteBase64 = Base64.encode(cert.getEncoded());
		return new String(byteBase64);
	}
	
	//Converte una stringa base64 iu un certificato
	protected X509Certificate convBase64ToX509(String base64Cert) throws CertificateException, NoSuchProviderException{
		byte[] data = Base64.decode(base64Cert);
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(data));
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
		stm.executeUpdate("DELETE FROM tblSeriale;");
		stm.executeUpdate("INSERT INTO tblSeriale VALUES ('" + newSerial + "');");
	}
	
	//Inserisce un nuovo record nei certifiati della CA
	protected void insertCACert(String serial, String privKey, String pubKey, String cert) throws SQLException{
		Connection conn1 = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	    Statement stm = conn1.createStatement();
		stm.executeUpdate("INSERT INTO tblCACert (serialNumber, privateKey, publicKey, cert) VALUES ('" + serial + "', '" + privKey + "', '" + pubKey + "', '" + cert + "');");
		stm.close();
		conn1.close();
	}
	
	//Inserisce un certificato nella tabella dei revocati
	protected void insertRevokedCert(String serial, int reason) throws SQLException{
		String date = convDateToString(getDate());
	    PreparedStatement ps = conn.prepareStatement("INSERT INTO tblRevokedCert (serialNumber, opDate, reason) VALUES (?, ?, ?);");
		ps.setString(1, serial);
		ps.setString(2, date);
		ps.setInt(3, reason);
		ps.executeUpdate();	
	}
	
	//Inserisce un nuovo certificato tra quelli degli utenti
	protected void insertUsrCert(String cert, String state, String notAfter, String notBefore, String serialNumber, String subjectDN, String reason) throws SQLException{
	    //Statement stm = conn1.createStatement();
		PreparedStatement ps = conn.prepareStatement( "INSERT INTO tblUsrCert (cert, state, notAfter, notBefore, serialNumber, subjectDN, reason)" +
				                                    "VALUES (?, ?, ?, ?, ?, ?, ?);");
		ps.setString(1, cert);
		ps.setString(2, state);
		ps.setString(3, notAfter);
		ps.setString(4, notBefore);
		ps.setString(5, serialNumber);
		ps.setString(6, subjectDN);
		ps.setString(7, reason);
		ps.executeUpdate();	
		//incSerial();
		ps.close();
	}
	
	/**
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
		stm1.executeQuery("INSERT INTO  tblRinnovi (data, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getNowStringDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "';");
		stm1.close();
		conn1.close();
	}
	*/
	
	//Inserisce un nuovo aggiornamento nella tabella dei rinnovi
	protected void insertRinnCert(String serial, String newNotBefore, String oldNotBefore) throws SQLException{
	    Statement stm1 = conn.createStatement();
		stm1.executeUpdate("INSERT INTO  tblRinnovi (dataOP, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getNowStringDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "');");
		stm1.close();
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

	
	
	//Ottiene il seriale del DB
	protected int getSerialToDB() throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSeriale");
		int lastSerial = 1000;
		if (rs.next()){
			lastSerial = rs.getInt("serial");
		}else{
			lastSerial = 1000;
			setSerialInDB(1000);
		}
		return lastSerial;
	}
	
	/**
	//Controlla se il seriale è già usato nel DB
	@SuppressWarnings("unused")
	private boolean serialAlreadyExist(String serialNumber) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsrCert WHERE serialNumber = '" + serialNumber + "';");
		return rs.next();
	}*/
	
	
	//Controlla se il subjectDN è già usato nel DB
	private boolean userAlreadyExist(String subjectDN) throws SQLException{
	    Statement stm = conn.createStatement();
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsers WHERE subjectDN = '" + subjectDN + "';");
		return rs.next();
	}
	
	//Restituisce la lista degli utenti della CA
	protected ResultSet getCAUser() throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT subjectDN from tblUsers;" );
	}
	
	//Restituisce tutti i certificati validi di un utente
	protected ResultSet getValidUserCert(String user) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE state = 'good' AND subjectDN = '" + user + "';" );
	}
	
	//Restituisce tutti i certificati di un utente
	protected ResultSet getListUserCert(String user) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE subjectDN = '" + user + "';" );
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
	protected ResultSet getUserCert(String serial) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN, reason FROM tblUsrCert WHERE serialNumber = '" + serial +"';");
	}
	
	//Restituisce il certificato della CA
	protected ResultSet getCACert(String serial) throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT cert FROM tblCACert;");	
	}
	
	//Restituisce la lista dei certificati revocati
	protected ResultSet getRevokedCert() throws SQLException{
	    Statement stm = conn.createStatement();
		return stm.executeQuery("SELECT serialNumber, reason, opDate FROM tblRevokedCert;");
	}
	
	//Setta lo stato di un certificato
	protected void setStateCert(String serial, String state, int reason) throws SQLException{
	    Statement stm = conn.createStatement();
		stm.executeUpdate("UPDATE tblUsrCert SET state = '"+ state +"', reason = '" + reason + "' WHERE serialNumber = '" + serial + "';");
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
		stm.executeUpdate("DELETE FROM tblUsrCert WHERE serialNumber = '" + serial + "';");
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
