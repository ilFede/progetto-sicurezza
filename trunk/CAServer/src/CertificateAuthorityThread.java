import java.util.*;
import java.math.BigInteger;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.sql.Date;
import java.io.*;
import java.io.*;
import java.net.*;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import java.sql.Date;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;


import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class CertificateAuthorityThread extends Thread {
	private static int num;
	private int id;
	private Statement stm;
	private Socket conn;
	private BufferedReader in;
	private BufferedWriter out;
	
	public CertificateAuthorityThread(Socket conn, Statement stm) throws IOException{
		id = num;
		num += 1;
		this.conn = conn;
		this.stm = stm;
		in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));		
	}
	
	public String recieve() throws IOException{
		String s = in.readLine();
		return s;
	}
	
	public void send(String s) throws IOException{
		out.write(s);
	}
	
	public void closeConnection() throws IOException{
		in.close();
		out.close();
		conn.close();
	}
	
	public void insertCert(String userMail, String from, String to, String publicKey, String privateKey) throws SQLException {
		stm.executeQuery("INSERT INTO userCertificate (userCertificate.userMail, publicKey, privateKey, userCertificate.from, userCertificate.to, userCertificate.creationDate) VALUES ('" + userMail + "'.'" + publicKey + "'.'"+ privateKey + "'.'"+ from + "'.'" + to + "','" + getDate() + "');");		
	}
	
	public void renewalCert(String idCert, String newTo) throws SQLException{
		ResultSet result;
		result = stm.executeQuery("SELECT userCertificate.to WHERE userCertificate.id = '" + idCert + ",;");
		result.first();
		int oldTo = result.getInt(0);
		stm.executeQuery("UPDATE userCertificate SET userCertificate.to = '" + newTo + " WHERE userCertificate.id = " + idCert + "';");
		stm.executeQuery("INSERT INTO  renewalCert (renewalCert.dateOperation, renewalCert.certId, renewalCertoldTo, renewalCertnewTo) VALUES ('" + getDate() + "','"+ idCert + "','" + oldTo + "','" + newTo + "';");
	}
	
	public void revocationCert(String idCert) throws SQLException{
		stm.executeQuery("UPDATE userCertificate SET userCertificate.state = 'Revocated' WHERE userCertificate.id = " + idCert + "';");
	}
	 
	public String getCertState(String idCert) throws SQLException {
		ResultSet result = (stm.executeQuery("SELECT userCertificate.state WHERE userCertificate.id = '" + idCert + ",;"));
		result.first();
		return result.getString(0);
	}
	
	public void insertUser(String commonName, String organization, String email, String organizationUnit, String locality, String state, String country) throws SQLException{
		stm.executeQuery("INSERT INTO user (user.commonName, user.organization, user.email, user.organizationUnit, user.locality, user.state, user.country) VALUES ('" + commonName + "','" + organization + "','" + organizationUnit + "','" + locality + "','" + state + "','" + country + "');");
		
	}
	
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
	}
	
	public X509Certificate createCert(Date startDate, Date expiryDate, BigInteger serialNumber, 
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
	
	public void run(){
		String s = "";
		while (!s.equals("stop")){
			try {
				s = recieve();
				System.out.println("Il thread " + id + " ha ricevuto: " + s);
			} catch (IOException e) {
				System.out.println("Error!!!!/n" + e);
			}
			System.out.println(s);
			
		}
		try {
			closeConnection();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
