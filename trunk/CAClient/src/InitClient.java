import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.StringWriter;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


public class InitClient extends DBQueryClient{
	
	protected Properties dbAccess;
	protected Socket conn;
	protected BufferedReader in;
	protected PrintStream out;
	protected String username;
	protected String password;
	protected String dbClassName;
	protected String dbPath;
	protected PublicKey caPk;
	protected boolean newUsr;
	
	public InitClient(String dbClassName, String dbPath, String username, String password, String host, int port, boolean newUsr) throws SQLException, ClassNotFoundException{
		super(dbClassName, dbPath);
		try{
			conn = new Socket(host, port);
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			out = new PrintStream(conn.getOutputStream());	
			this.username = username;
			this.password =  password;
			this.newUsr = newUsr;
			this.dbPath = dbPath;
			this.dbClassName = dbClassName;
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	public ClientCA inizializeClient(){
		if ((recievePubKey() == true) && (ckeckUser() == true)){
			try{
				return new ClientCA(username, dbClassName, dbPath, conn, caPk);
			}catch (Exception e){
				return null;
			}
		}else{
			return null;
		}
	}
	
	public boolean chekData(){
		return ((recievePubKey() == true) && (ckeckUser() == true));
	}
	
	public boolean recievePubKey(){
		try{
			DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
	        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
	        Document doc = docBuilder.newDocument();
	        //create the root element and add it to the document
	        Element root = doc.createElement("message");
	        root.setAttribute("operation", "sendCaPubKey");
	        sendWithoutDigest(root);
	        String document3 = in.readLine();
	        while(in.ready()){
	        	document3 = document3 + "\n" + in.readLine();
	        }
			Document response3 = convStringToXml(document3);
			Node operation3 = (response3.getElementsByTagName("caPublicKey").item(0));
			String result = operation3.getChildNodes().item(0).getNodeValue();
			caPk = convBase64ToPubKey(result);
			return true;
		}catch(Exception e){
			return false;
		}
	}
	
	public boolean ckeckUser(){
		try{
			if (newUsr == true){
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		        Document doc = docBuilder.newDocument();
		        //create the root element and add it to the document
		        Element root = doc.createElement("message");
		        root.setAttribute("operation", "checkUser");
		        Element certEl = doc.createElement("user");
		        certEl.appendChild(doc.createTextNode(username));
		        root.appendChild(certEl);
		        sendWithoutDigest(root);
		        System.out.println("Inizio a leggere....");
		        String document = in.readLine();
		        while(in.ready()){
		        	document = document + "\n" + in.readLine();
		        }
		        System.out.println("ho letto la risposta\n" + document);
				Document response = convStringToXml(document);
				Node operation = (response.getElementsByTagName("result").item(0));
				String result = operation.getChildNodes().item(0).getNodeValue();
				if (result.equals(false + "")){
					DocumentBuilderFactory dbfac1 = DocumentBuilderFactory.newInstance();
			        DocumentBuilder docBuilder1 = dbfac1.newDocumentBuilder();
			        Document doc1 = docBuilder1.newDocument();
			        Element root1 = doc1.createElement("message");
			        root1.setAttribute("operation", "insertNewUser");
			        Element certEl1 = doc1.createElement("user");
			        certEl1.appendChild(doc1.createTextNode(username));
			        root1.appendChild(certEl1);
					sendWithoutDigest(root1);
					System.out.println("ho spedito la richiesta");
					String document3 = in.readLine();
			        while(in.ready()){
			        	document3 = document3 + "\n" + in.readLine();
			        }
					Document response3 = convStringToXml(document3);
					Node operation3 = (response3.getElementsByTagName("result").item(0));
					String result3 = operation3.getChildNodes().item(0).getNodeValue();
					if (result3.equals(true + "")){
						inizializeDb();
						insertUserInDb();
						return true;
					}else{
						return false;
					}
				}else{
					return false;
	
				}
			}else{
				boolean b = checkLogin();
				return b;
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
			return false;
		}
	}
	
	/**public boolean canConnect(){
		try{
			if (newUsr == true){
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		        Document doc = docBuilder.newDocument();
		        //create the root element and add it to the document
		        Element root = doc.createElement("message");
		        root.setAttribute("operation", "checkUser");
		        Element certEl = doc.createElement("user");
		        certEl.appendChild(doc.createTextNode(username));
		        root.appendChild(certEl);
		        sendWithoutDigest(root);
		        System.out.println("Inizio a leggere....");
		        String document = in.readLine();
		        while(in.ready()){
		        	document = document + "\n" + in.readLine();
		        }
		        System.out.println("ho letto la risposta\n" + document);
				Document response = convStringToXml(document);
				Node operation = (response.getElementsByTagName("result").item(0));
				String result = operation.getChildNodes().item(0).getNodeValue();
				if (result.equals(false + "")){
					DocumentBuilderFactory dbfac1 = DocumentBuilderFactory.newInstance();
			        DocumentBuilder docBuilder1 = dbfac1.newDocumentBuilder();
			        Document doc1 = docBuilder1.newDocument();
			        Element root1 = doc1.createElement("message");
			        root1.setAttribute("operation", "insertNewUser");
			        Element certEl1 = doc1.createElement("user");
			        certEl1.appendChild(doc1.createTextNode(username));
			        root1.appendChild(certEl1);
					sendWithoutDigest(root1);
					System.out.println("ho spedito la richiesta");
					String document3 = in.readLine();
			        while(in.ready()){
			        	document3 = document3 + "\n" + in.readLine();
			        }
					Document response3 = convStringToXml(document3);
					Node operation3 = (response3.getElementsByTagName("result").item(0));
					String result3 = operation3.getChildNodes().item(0).getNodeValue();
					if (result3.equals(true + "")){
						inizializeDb();
						insertUserInDb();
						return true;
					}else{
						return false;
					}
				}else{
					return false;
	
				}
			}else{
				boolean b = checkLogin();
				return b;
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
			return false;
		}
	}*/
	
	protected boolean checkLogin() throws SQLException{
		ResultSet rs = getLogin();
		rs.next();
		String userdb = rs.getString(1);
		String passdb = rs.getString(2);
		return ((userdb.equals(username))&&(passdb.equals(password)));
	}
	
	protected void insertUserInDb() throws SQLException{
		insertUser(username, password);
	}
	
	//Invia un messaggio senza firmarlo
	protected void sendWithoutDigest(Element elem) throws TransformerException, IOException{	
		//String xmlString = convXMLToString(elem);
		String message = "<document>\n" + convXmlToString(elem) + "</document>\n";
		System.out.println(message);
		out.println(message);
		System.out.println("messaggio spedito");
	}
	
	//Converte una stringa in un Document XML
	protected Document convStringToXml(String s) throws SAXException, IOException, ParserConfigurationException{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder parser = factory.newDocumentBuilder();
	    Document d = parser.parse(new ByteArrayInputStream(s.getBytes()));
	    return d;
	}
	
	//Converte un Document XML in una stringa
	protected String convXmlToString (Element doc) throws TransformerException{
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
	
	//Converte una stringa BASE64 in una chiave pubblica
	protected static PublicKey convBase64ToPubKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] publicKeyBytes =  Base64.decode(publicKey);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}

}
