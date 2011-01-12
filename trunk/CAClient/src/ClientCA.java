import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.StringWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class ClientCA{
	protected static int num;
	protected int id;
	protected Socket clientConn;
	protected BufferedReader in;
	protected PrintStream out;
	protected String user;
	protected PublicKey caPubKey;
	protected MessageWindows window;
	protected final String DIGEST_SIGN_ALG = "MD2withRSA";
	protected final String GOOD = "good";
	protected final String REVOKED = "revoked";
	protected final String EXPIRED = "expired";
	protected final String CANAME = "FedeCA";
	protected final String CRL_SIGN_ALG = "MD2withRSA";
	protected final String OP_FAIL = "false";
	
	private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
	private String username;
	
	
	//Costruttore
	public ClientCA(String username, String dbClassName, String dbPath, Socket clientConn, PublicKey caPk) throws SQLException, ClassNotFoundException{
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider ());
		Class.forName("org.sqlite.JDBC"); 
		this.username = username;
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.caPubKey=caPk;
		
		caPubKey = caPk;
		try{
			in = new BufferedReader(new InputStreamReader(clientConn.getInputStream()));
			out = new PrintStream(clientConn.getOutputStream());	
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
		id = num;
		num+=1; 
		window = new MessageWindows("Messaggi" + username);
		System.out.println("Ci sosdad");
		window.open();
		//System.out.println("Il numero è: " + num);
		//boolean b = sendRevokeRequest("1012", 1, "1012");
		//System.out.println("Il risultato dell'operazione è: " + b);
		
		/**
		ArrayList<String> array = recieveUrsList();
		System.out.println("Certtificati validi: ");
		for (int i = 0; i < array.size(); i++){
			System.out.println(array.get(i));
		}*/
		//X509CRL crl = sendCrlRequest();
		//System.out.println(crl.toString());
		//recieveCaPubKey();
		
		//String user = getUsername().getString(1);
	}
	
	//Metodi per la comunicazione col server
	
	//Riceve un messaggio
	protected String recieve(){
		try{
			while(!in.ready()){
			}
			String document = "";
	        while(in.ready()){
	        	document = document + "\n" + in.readLine();
	        }
	        window.write("--------------- Messaggio rievuto: ---------------\n" + document + "-------------------------------\n");
	        System.out.println(document);
	        return document;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Controlla se l'operazione ha avuto successo
	protected boolean checkSuccess(Document doc){
		Node messNode = (doc.getElementsByTagName("message").item(0));
		System.out.println("fattoooo");

		Node opSucc = messNode.getAttributes().item(1);
		System.out.println("fatoooo");

		String succ = opSucc.getNodeValue();
		System.out.println("Il risultato dell'operazione è: " + succ);
		return succ.equals("true");
	}
	
	//Invia un messaggio firmandolo
	protected void sendWithDigest(Element elem, PrivateKey privKey){
		try{
			String xmlString = convXMLToString(elem);
			PrivateKey key = privKey;
			String digest = createDigest(xmlString, key);
			String message = "<document sender=\""+ username +"\">\n" + convXMLToString(elem) + "<digest>\n" + digest + "\n</digest>\n</document>";
	        window.write("--------------- Messaggio inviato: ---------------\n" + message + "\n-------------------------------\n");
	        System.out.println(message);
			out.println(message);
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	//Invia un messaggio senza firma
	protected void sendWithoutDigest(Element elem){
		try{
			//String xmlString = convXMLToString(elem);
			String message = "<document sender=\""+ username +"\">\n" + convXMLToString(elem) + "</document>\n";
	        window.write("--------------- Messaggio inviato: ---------------\n" + message + "\n-------------------------------\n");
	        System.out.println(message);
			out.println(message);
			//out.flush();
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
			Document response = convStringToXml(document);
			Node message = (response.getElementsByTagName("message").item(0));
			String caPubKeyString = message.getChildNodes().item(0).getTextContent();
			return convBase64ToPubKey(caPubKeyString);
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
			
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){	
				boolean check = checkSuccess(response);
				if (check == true){
					NodeList message = (response.getElementsByTagName("user"));
					System.out.println("Ho trovato la bellezza di " + message.getLength());
					return convNodeListToArrayList(message);
				}else{
					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Riceve la lista dei certificati validi di un utente
	protected ArrayList<String> recieveValidCertUsrList(String serialUser){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendValidUsrCert");
			Element e1 = doc.createElement("user");
            e1.appendChild(doc.createTextNode(serialUser));
            root.appendChild(e1);
			sendWithoutDigest(root);
			
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){	
				System.out.println("Controllo il chek");
				boolean check = checkSuccess(response);
				if (check == true){
					System.out.println("il chek va bene");
					NodeList message = (response.getElementsByTagName("cert"));
					System.out.println("Ho trovato la bellezza di " + message.getLength());
					return convNodeListToArrayList(message);
				}else{
					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Riceve la lista dei certificati validi di un utente
	protected ArrayList<String> recieveRenewableCertUsrList(String serialUser){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendRenewableUsrCert");
			Element e1 = doc.createElement("user");
            e1.appendChild(doc.createTextNode(serialUser));
            root.appendChild(e1);
			sendWithoutDigest(root);
			
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){	
				System.out.println("Sto controllando il cke..");
				boolean check = checkSuccess(response);
				if (check == true){
					System.out.println("iva bene");

					NodeList message = (response.getElementsByTagName("cert"));
					return convNodeListToArrayList(message);
				}else{
					System.out.println("non va bene");

					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Riceve la lista dei certificati validi di un utente
	protected ArrayList<String> recieveCertUsrList(String serialUser){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendUsrCert");
			Element e1 = doc.createElement("user");
            e1.appendChild(doc.createTextNode(serialUser));
            root.appendChild(e1);
			sendWithoutDigest(root);
			
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){			
				boolean check = checkSuccess(response);
				if (check == true){
					NodeList message = (response.getElementsByTagName("cert"));
					return convNodeListToArrayList(message);
				}else{
					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	protected boolean renewsCertificate(String certificateSerial, String newNotBefore, String serialPk, int l){
		try{
			System.out.println("entrato");
			KeyPair chiavi = createKeyPair(l);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "renewsCertificate");
			Element e1 = doc.createElement("serial");
            e1.appendChild(doc.createTextNode(serialPk));
            Element e2 = doc.createElement("newNotBefore");
            e2.appendChild(doc.createTextNode(newNotBefore));
            Element e3 = doc.createElement("publicKey");
            e3.appendChild(doc.createTextNode(convPubKeyToBase64(chiavi.getPublic())));
            Element e4 = doc.createElement("serialSign");
            e4.appendChild(doc.createTextNode(serialPk));
            root.appendChild(e1);
            root.appendChild(e2);
            root.appendChild(e3);
            root.appendChild(e4);
			System.out.println("sono arrivato fi qui");

			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		    stm = conn.createStatement();
			System.out.println("sono arrivato fi qui2");

			ResultSet rs = getPrivKeyToDB(serialPk);

			System.out.println("mi sono fatto dare il result set");

			String privKeyToDigest = rs.getString(1);
			System.out.println("La chiave estretta è " + privKeyToDigest);
			PrivateKey keyDigest = convBase64ToPrivKey(privKeyToDigest);
			System.out.println("mi sono fatto dare la chiave");

			conn.close();
			System.out.println("Ho chiuso la connessione!!");
			sendWithDigest(root, keyDigest);
			
			String messaggio = recieve();
			
	        
			Document response = convStringToXml(messaggio);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){
				boolean check = checkSuccess(response);
				if (check == true){
					System.out.println("Entrato!!!!!");
					String serial = (response.getElementsByTagName("serial").item(0)).getChildNodes().item(0).getNodeValue();
					String cert = (response.getElementsByTagName("cert").item(0)).getChildNodes().item(0).getNodeValue();
					System.out.println("Ho letto i dati" + serial + cert);
					conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
					stm = conn.createStatement();
					deleteUsrCert(serial);
					conn.close();
					System.out.println("Ci sono!!!!!!");
					conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
				    stm = conn.createStatement();
					insertUsrCert(serial, convPubKeyToBase64(chiavi.getPublic()), convPrivKeyToBase64(chiavi.getPrivate()), cert);

					conn.close();
					return true;
				}else{
					return false;
				}
			}else{
				System.out.println("firma non valida");
				return false;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		    return false;
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
			
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){	
				boolean b = checkSuccess(response);
				if (b == true){
					//Node message = (response.getElementsByTagName("message").item(0));
					return convOCSPToArrayList(response);
				}else{
					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Richeide un nuovo certificato autofirmato
	protected boolean certificateSSRequest(String notAfter, String notBefore, String subjectDN, String signatureAlg, String organizationUnit, int l){
		try{
			System.out.println("Inizio a creare i dati da inviare");
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
			Element sDN = doc.createElement("subjectDN");
	        sDN.appendChild(doc.createTextNode(username));
			root.appendChild(sDN);
			Element pk = doc.createElement("publicKey");
	        pk.appendChild(doc.createTextNode(convPubKeyToBase64(kp.getPublic())));
			root.appendChild(pk);
			Element sigAl = doc.createElement("signatureAlg");
	        sigAl.appendChild(doc.createTextNode(signatureAlg));
			root.appendChild(sigAl);
			Element ou = doc.createElement("organizationUnit");
	        ou.appendChild(doc.createTextNode(organizationUnit));
			root.appendChild(ou);
			System.out.println("Ho creato i dati");

			sendWithoutDigest(root);
			//Risposta
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			System.out.println("La firma è " + digestOk);
			if (digestOk == true){	
				boolean b = checkSuccess(response);
				if (b == true){
					String serial = (response.getElementsByTagName("serial").item(0)).getChildNodes().item(0).getNodeValue();
					String cert = (response.getElementsByTagName("cert").item(0)).getChildNodes().item(0).getNodeValue();
					conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
				    stm = conn.createStatement();
					insertUsrCert(serial, convPubKeyToBase64(kp.getPublic()), convPrivKeyToBase64(kp.getPrivate()), cert);
					conn.close();
					return true;
				}else{
					return false;
				}
			}else{
				System.out.println("firma non valida");
				return false;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
		    return false;
		}
	}
	
	//Richeide un nuovo certificato autofirmato
	protected boolean certificateRequest(String notAfter, String notBefore, String subjectDN, String signatureAlg, String organizationUnit, int l, String pkserial){
		try{
			KeyPair kp = createKeyPair(l);
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "createNewCertificate");
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
			Element ou = doc.createElement("organizationUnit");
	        ou.appendChild(doc.createTextNode(organizationUnit));
			root.appendChild(ou);
			Element e4 = doc.createElement("serialSign");
            e4.appendChild(doc.createTextNode(pkserial));
            root.appendChild(e4);
            Element e5 = doc.createElement("subjectDN");
            e5.appendChild(doc.createTextNode(username));
            //e5.appendChild(doc.createTextNode("CN=" + username));
            root.appendChild(e5);
			System.out.println("Tento la query");
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		    stm = conn.createStatement();
			ResultSet rs = getPrivKeyToDB(pkserial);
			
			System.out.println("Ho fatto la query su /" + pkserial +"/");
			rs.next();
			PrivateKey privk = convBase64ToPrivKey(rs.getString(1));
			sendWithDigest(root, privk);
			conn.close();
			String document = recieve();
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){	
				boolean b = checkSuccess(response);
				if (b == true){
					String serial = (response.getElementsByTagName("serial").item(0)).getChildNodes().item(0).getNodeValue();
					String cert = (response.getElementsByTagName("cert").item(0)).getChildNodes().item(0).getNodeValue();
					conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
				    stm = conn.createStatement();
					insertUsrCert(serial, convPubKeyToBase64(kp.getPublic()), convPrivKeyToBase64(kp.getPrivate()), cert);
					conn.close();
					return true;
				}else{
					return false;
				}
			}else{
				System.out.println("firma non valida");
				return false;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	//Invia la richiesta di revoca di un certificato
	protected boolean sendRevokeRequest(String serial, int reason, String pkSerial){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "revokeCert");
			Element sr = doc.createElement("serial");
		    sr.appendChild(doc.createTextNode(serial));
			root.appendChild(sr);
			Element ss = doc.createElement("serialSign");
		    ss.appendChild(doc.createTextNode(pkSerial));
		    root.appendChild(ss);
			Element mot = doc.createElement("reason");
		    mot.appendChild(doc.createTextNode(reason + ""));
			root.appendChild(mot);
			conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		    stm = conn.createStatement();
			ResultSet rs = getPrivKeyToDB(pkSerial);
			rs.next();
			PrivateKey privk = convBase64ToPrivKey(rs.getString(1));
			conn.close();
			sendWithDigest(root, privk);
			//Risposta
			String messaggio = recieve();
			
			Document response = convStringToXml(messaggio);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){
				boolean check = checkSuccess(response);
				if (check == true){
					return true;
				}else{
					return false;
				}
			}else{
				System.out.println("firma non valida");
				return false;
			}	
		}catch(Exception e){
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	//Chiede la CRL
	protected X509CRL sendCrlRequest(){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
			Document doc = docBuilder.newDocument();
			//create the root element and add it to the document
			Element root = doc.createElement("message");
			root.setAttribute("operation", "sendCrl");
			//conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
		    //stm = conn.createStatement();
			//ResultSet rs = getPrivKeyToDB(pkserial);
			//rs.next();
			//PrivateKey privk = convBase64ToPrivKey(rs.getString(1));
			//conn.close();
			sendWithoutDigest(root);
			//Risposta
			String document = recieve();	
			Document response = convStringToXml(document);
			boolean digestOk = checkDigest(response);
			if (digestOk == true){
				boolean check = checkSuccess(response);
				if (check == true){
					String crlString = response.getElementsByTagName("crl").item(0).getChildNodes().item(0).getNodeValue();
					System.out.println("Ho ricevuto la cRL " + crlString);
					X509CRL crl = convBase64ToCrl(crlString);		
					return crl;
				}else{
					return null;
				}
			}else{
				return null;
			}
		}catch(Exception e){
			System.out.println(e.getMessage());
			return null;
		}	
	}
			
	/**public void closeConnection() throws IOException{
		in.close();
		out.close();
		clientConn.close();
	}*/
	
	/**public void send (String s) throws IOException{
		out.write("Client " + num + ": ");
		out.write(s);
		out.newLine();
		out.flush();
	}
	 * @throws InvalidKeySpecException */
	
	//Metodi per esegiure le operazioni
	
	//Crea un coppia di chiavi
	private KeyPair createKeyPair(int l) throws NoSuchAlgorithmException, InvalidKeySpecException{     
		//inizializza un generatore di coppie di chiavi usando RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(l);
        //kpg.initialize(l, new SecureRandom( ));
        // genera la coppia
        KeyPair kp = kpg.generateKeyPair();
        String kpr = convPrivKeyToBase64(kp.getPrivate());
        //PrivateKey rrr = convBase64ToPrivKey(kpr);
        String kpr2 = convPrivKeyToBase64(kp.getPrivate());
        System.out.println("La chiave priva geerata è " + kpr2 + "\n" + kpr);
        return kp;
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
	protected boolean checkDigest(Document doc) throws SignatureException, NoSuchAlgorithmException, TransformerException, InvalidKeyException{
		System.out.println("ricevuto mess");
		String message = getMessage(doc);
		System.out.println("estratto mess\n" + message);
		String digest64 = getDigest64(doc);
		System.out.println("estratto digest\n" + digest64);
		//String sender = getSender(doc);
		Signature s = Signature.getInstance(DIGEST_SIGN_ALG);
		
		System.out.println("Aggiornato");
		s.initVerify(caPubKey);
		System.out.println("Inizializzato");
		s.update(message.getBytes());
		System.out.println("printo");
		boolean digestOK = s.verify(Base64.decode(digest64));
		System.out.println("Il risultato ella firma è" + digestOK);
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
		String month = ("0" + date.getMonth() + 1);
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + date.getDay());
		day = day.substring(day.length() - 2, day.length());
		return day + "/" + month + "/" + year;
	}
	
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
	
	*/
	/**
	//Converte una stringa BASE64 in una chiave pubblica
	protected static PublicKey convBase64ToPubKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] publicKeyBytes =  Base64.decode(publicKey);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}
	
	//Converte una stringa BASE64 in una chiave privata
	protected static PrivateKey convBase64ToPrivKey(String privateKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] privateKeyBytes = Base64.decode(privateKey);
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(ks);
	}*/
	
	/*
	//converte una chiave privata in una stringa
	protected static String convPrivKeyToString(PrivateKey key){
		return new String(Base64.encode(key.getEncoded()));
	}
	
	//converte una chiave pubblica in una stringa
	protected static String convPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}*/
	
	//Converte una chiave privata in una stringa Base64
	public static String convPrivKeyToBase64(PrivateKey key){
		byte[] tmp = key.getEncoded();
		byte[] conv = Base64.encode(tmp);
		return new String(conv);
	}
	
	//Converte una chiave pubblica in una stringa Base64
	public static String convPubKeyToBase64(PublicKey key){
		byte[] tmp = key.getEncoded();
		byte[] conv = Base64.encode(tmp);
		return new String(conv);
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
	
	//Converte un resultSet in un Vector
	protected ArrayList<String> convNodeListToArrayList(NodeList node){
		ArrayList<String> array = new ArrayList<String>();
		int l = node.getLength();
		System.out.println("Ho trovato elemte" + l);
		for(int i = 0; i < l; i++){
			String elemento = node.item(i).getChildNodes().item(0).getNodeValue();
			System.out.println("Aggiungo: " + elemento);
			array.add(elemento);
		}
		return array;
	}
	
	//Converto OCSP in array list
	protected ArrayList<String> convOCSPToArrayList(Document doc){
		ArrayList<String> array= new ArrayList<String>();
		String cert = doc.getElementsByTagName("cert").item(0).getChildNodes().item(0).getNodeValue();
		String state = doc.getElementsByTagName("state").item(0).getChildNodes().item(0).getNodeValue();
		String notAfter = doc.getElementsByTagName("notAfter").item(0).getChildNodes().item(0).getNodeValue();
		String notBefore = doc.getElementsByTagName("notBefore").item(0).getChildNodes().item(0).getNodeValue();
		String serialNumber = doc.getElementsByTagName("serialNumber").item(0).getChildNodes().item(0).getNodeValue();
		String subjectDN = doc.getElementsByTagName("subjectDN").item(0).getChildNodes().item(0).getNodeValue();
		String reason = doc.getElementsByTagName("reason").item(0).getChildNodes().item(0).getNodeValue();
		array.add(cert);
		array.add(state);
		array.add(notAfter);
		array.add(notBefore);
		array.add(serialNumber);
		array.add(subjectDN);
		array.add(reason);
		return array;
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
	
	//Converte una stringa Base64 in una X509CRL
	protected X509CRL convBase64ToCrl(String crlString) throws CertificateException, NoSuchProviderException, CRLException{
		ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decode(crlString));
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = (X509CRL) fact.generateCRL(bais);
        return crl;
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
	
	//Query
	
	//Restituisce il nome dell'utente
	protected ResultSet getUsername() throws SQLException{
		return stm.executeQuery("SELECT username FROM tblUsr;");
	}
	
	//Restituisce la password dell'utente
	protected ResultSet getPassword() throws SQLException{
		return stm.executeQuery("SELECT password FROM tblUsr;");
	}
	
	//Restituisce la chiave privata di un cxertificato
	protected ResultSet getPrivKeyToDB(String serial) throws SQLException{
		return stm.executeQuery("SELECT privateKey FROM tblUsrCert WHERE serialNumber = '" + serial + "';");
	}
	
	//Inserisce un nuovo certificato nel DB
	protected void insertUsrCert(String serial, String pubKey, String privKey, String cert) throws SQLException{
		stm.executeUpdate("INSERT INTO tblUsrCert(serialNumber, publicKey, privateKey, cert) VALUES ('" + serial + "', '" + pubKey + "', '" + privKey + "', '" + cert + "');");
	}
	
	//Metodo che inizializza il db
	protected void inizializeDb() throws SQLException{
		stm.executeUpdate("DROP TABLE IF EXISTS tblUsrCert;");
		stm.executeUpdate("DROP TABLE IF EXISTS tblUsr;");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsrCert (cert TEXT, privateKey TEXT, publicKey TEXT, serialNumber TEXT);");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsr (password TEXT, subjectDN TEXT);");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsrCert (cert TEXT, privateKey TEXT, publicKey TEXT, serialNumber TEXT);");
	}
	
	//Metodo che inserisce l'utente nel db
	protected void insertUser(String user, String password) throws SQLException{
		stm.executeUpdate("INSERT INTO tblUsr (subjectDN, password) VALUES ('" + user + "', '" + password + "');");
	}
	
	//Metodo che restituisce le credenziali di accesso
	protected ResultSet getLogin() throws SQLException{
		return stm.executeQuery("SELECT subjectDN, password FROM tblUsr");
	}
	
	//Metodo che restituisce un certificato di un utente
	protected ResultSet getUsrCert(String serial) throws SQLException{
		return stm.executeQuery("SELECT cert FROM tblUsrCert WHERE serialNumber = '" + serial + "';");
	}
	
	//Elimina un certificato
	protected void deleteUsrCert(String serial) throws SQLException{
		stm.executeUpdate("DELETE FROM tblUsrCert WHERE serialNumber = '" + serial + "';");
	}
}