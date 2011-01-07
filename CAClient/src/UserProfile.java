import java.io.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Node;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

public class UserProfile {
	private String commonName, organization, mail, organizationUnit, locality, state, country, path;
	private final String fileName = "profile.xml";
	
	public UserProfile (String path, String fileName){
		try {
			/* Uso un file XML per ogni profilo così li posso caricare anche da altre applizazioni. Se usassi
			 * un database avrei problemi ad importare un solo utente
			 */			
			File file = new File(path + fileName);
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(file);
			//doc.getDocumentElement().normalize();
			commonName = doc.getElementsByTagName("commonName").item(0).getChildNodes().item(0).getNodeValue();
			organization = doc.getElementsByTagName("organization").item(0).getChildNodes().item(0).getTextContent();
			mail = doc.getElementsByTagName("mail").item(0).getChildNodes().item(0).getNodeValue();
			organizationUnit = doc.getElementsByTagName("organizationUnit").item(0).getChildNodes().item(0).getNodeValue();
			locality = doc.getElementsByTagName("locality").item(0).getChildNodes().item(0).getNodeValue();
			state= doc.getElementsByTagName("state").item(0).getChildNodes().item(0).getNodeValue();
			country = doc.getElementsByTagName("country").item(0).getChildNodes().item(0).getNodeValue();
		}catch (Exception e){
			e.printStackTrace();
		}
	}
	
	public UserProfile (String commonName, String organization, String mail, String organizationUnit, String locality, String state, String country, String path){
		this.commonName = commonName;
		this.organization = organization;
		this.mail = mail;
		this.organizationUnit = organizationUnit;
		this.locality = locality;
		this.country = country;
		this.state = state;
		//Create XML file whit user's profile
		try {
            //Creating an empty XML Document
            DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = docBuilder.newDocument();
            //create the root element and add it to the document
            Element root = doc.createElement("userProfile");
            root.setAttribute("operation", "sadasd");
            doc.appendChild(root);
            //create a comment and put it in the root element
            root.appendChild(doc.createComment("Profilo \nutente"));
            //create child element and append it
            Element userEl = doc.createElement("user");
            Element commonNameEl = doc.createElement("commonName");
            commonNameEl.appendChild(doc.createTextNode(commonName));
            Element organizationEl = doc.createElement("organization");
            organizationEl.appendChild(doc.createTextNode(organization));
            Element mailEl = doc.createElement("mail");
            mailEl.appendChild(doc.createTextNode(mail));
            Element organizationUnitEl = doc.createElement("organizationUnit");
            organizationUnitEl.appendChild(doc.createTextNode(organizationUnit));
            Element localityEl = doc.createElement("locality");
            localityEl.appendChild(doc.createTextNode(locality));
            Element stateEl = doc.createElement("state");
            stateEl.appendChild(doc.createTextNode(state));
            Element countryEl = doc.createElement("country");
            countryEl.appendChild(doc.createTextNode(country));
            Element certificates = doc.createElement("myCertificates");
            userEl.appendChild(commonNameEl);
            userEl.appendChild(organizationEl);
            userEl.appendChild(mailEl);
            userEl.appendChild(organizationUnitEl);
            userEl.appendChild(localityEl);
            userEl.appendChild(stateEl);
            userEl.appendChild(countryEl);           
            root.appendChild(userEl);
            root.appendChild(doc.createComment("Certificati"));
            root.appendChild(certificates);
            //set up a transformer
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.setOutputProperty(OutputKeys.INDENT, "yes");
            //create file from xml tree
            StringWriter sw = new StringWriter();
            StreamResult result = new StreamResult(sw);
            DOMSource source = new DOMSource(root);
            trans.transform(source, result);
            String xmlString = sw.toString();
            FileOutputStream file = new FileOutputStream(path + commonName + ".usr");
            PrintStream output = new PrintStream(file);
            output.println(xmlString);

        } catch (Exception e) {
            System.out.println(e);
        }
        			
	}
	
	public String toString(){
		return commonName + " " + organization + " " + mail + " " + organizationUnit + " " + locality + " " + state + " " + country;
	}
	
	public static void main(String args []){
		UserProfile user1 = new UserProfile ("Federico", "MyOrg", "MyMail", "MyOrgUnit", "MyLocality", "MySate", "MyCountry", "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAClient/Profili/");
		System.out.println(user1.toString());
		UserProfile user2 = new UserProfile ("/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAClient/Profili/", "Federico.usr");
		System.out.println(user2.toString());
	}
	

}
