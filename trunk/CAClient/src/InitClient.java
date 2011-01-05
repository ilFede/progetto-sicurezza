import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.net.Socket;
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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


public class InitClient extends DBQueryClient{
	
	protected Properties dbAccess;
	protected Socket conn;
	protected BufferedReader in;
	protected BufferedWriter out;
	protected String username;
	protected String password;
	protected String dbClassName;
	protected String dbPath;
	protected boolean newUsr;
	
	public InitClient(String dbClassName, String dbPath, String username, String password, Properties dbAccess, String host, int port, boolean newUsr) throws SQLException{
		super(dbClassName, dbPath, dbAccess);
		try{
			conn = new Socket(host, port);
			in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));	
			this.dbAccess = dbAccess;
			this.username = username;
			this.password =  password;
			this.newUsr = newUsr;
			this.dbPath = dbPath;
			this.dbClassName = dbClassName;
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	public ClientCA connect(){
		if (canConnect()){
			try{
				return new ClientCA (dbClassName, dbPath, dbAccess, conn);
			}catch (Exception e){
				return null;
			}
		}else{
			return null;
		}
	}
	
	public boolean canConnect(){
		try{
			if (newUsr == true){
				DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
		        DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
		        Document doc2 = docBuilder.newDocument();
		        Element root = doc2.createElement("checkUser");
		        Element certEl = doc2.createElement("user");
		        certEl.appendChild(doc2.createTextNode(username));
		        sendWithoutDigest(root);
		        String document = in.readLine();	
				Document response = convStringToXml(document);
				Node operation = (response.getElementsByTagName("message").item(0)).getChildNodes().item(0);
				String result = operation.getChildNodes().item(0).getNodeValue();
				if (result.equals(false + "")){
					DocumentBuilderFactory dbfac1 = DocumentBuilderFactory.newInstance();
			        DocumentBuilder docBuilder1 = dbfac1.newDocumentBuilder();
			        Document doc1 = docBuilder1.newDocument();
			        Element root1 = doc1.createElement("insertNewUser");
			        Element certEl1 = doc1.createElement("user");
			        certEl1.appendChild(doc1.createTextNode(username));
					sendWithoutDigest(root1);
					
					String document3 = in.readLine();	
					Document response3 = convStringToXml(document3);
					Node operation3 = (response3.getElementsByTagName("message").item(0)).getChildNodes().item(0);
					String result3 = operation3.getChildNodes().item(0).getNodeValue();
					if (result3.equals(true + "")){
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
			return false;
		}
	}
	
	protected boolean checkLogin() throws SQLException{
		ResultSet rs = getLogin();
		rs.first();
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
		String message = "<document>/n" + convXmlToString(elem) + "/n</document>";
		out.write(message);
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

}
