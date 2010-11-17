import java.util.*;
import java.net.*;
import java.sql.*;
import java.io.*;

public class CertificateAuthority {
	
	private Statement stm;
	 ServerSocket sSocket;
	 
	public CertificateAuthority(String dbName, String name, String pass) throws SQLException, ClassNotFoundException, IOException{
		String dbClassName = "org.sqlite.JDBC";
		String connection = "jdbc:sqlite:./DataBase/test.db";
	    Class.forName(dbClassName);
	    Properties p = new Properties();
	    p.put("user", name);
	    p.put("password",pass);
	    stm = (DriverManager.getConnection(connection,p)).createStatement();
	    sSocket  = new ServerSocket(9999);
	}
	
	public void getConnection() throws IOException{
		Socket conn = sSocket.accept();
		CertificateAuthorityThread caThread = new CertificateAuthorityThread(conn, stm);
		caThread.start();		
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
}