import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Properties;


public class DBQuery {
	
	private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
	private Properties dbAccess;
	private int lastSerial; //primo seriale non usato, viene salvato in una cella del DB
	private final String GOOD = "good";
	private final String REVOKED = "revoked";
	private final String UNKNOWN = "unknown";
	
	public DBQuery(String dbClassName, String dbPath, Properties dbAccess) throws SQLException {
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.dbAccess = dbAccess;
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath, this.dbAccess));
	    stm = conn.createStatement();
	}
	
	//Ottiene l'ultimo seriale usato dalla tabella del DB
	protected void getSerialToDB() throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSeriale");
		if (rs.first()){
			lastSerial = rs.getInt("serial");
		}else{
			lastSerial = 1;
		}
	}
	
	//Imposta l'ultimo seriale usato nella tabella del BD
	protected void setSerialInDB(int newSerial) throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSerial;");
		if (rs.first()){
			stm.executeUpdate("UPDATE tblSeriale SET serial = " + newSerial + ";");
		}else{
			stm.executeUpdate("INSERT INTO tblSeriale VALUES (1);");
		}
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
	
	//Controlla se il seriale è già usato nel DB
	private boolean serialAlreadyExist(String serialNumber) throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsrCert WHERE serialNumber = '" + serialNumber + "';");
		return rs.first();
	}
	
	//Controlla se il subjectDN è già usato nel DB
	private boolean userAlreadyExist(String subjectDN) throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblUsers WHERE subjectDN = '" + subjectDN + "';");
		return rs.first();
	}
	
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
	}
	
	//Restituisce i certificati della CA validi
	protected ResultSet getCAKeyFromDB() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		return stm.executeQuery("SELECT privateKey, publicKey FROM tblCACert WHERE state = '" + GOOD +"';");	
	}
	
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
	}
	
	//Inserisce un nuovo certificato tra quelli degli utenti
	protected void insertUsrCert(String issuerDN, String notAfter, String notBefore, String publicKey, String signatureAlgorithm, String subjectDN, String state) throws SQLException{
		String serialNumber = getSerial() + "";
		PreparedStatement ps = conn.prepareStatement( "INSERT INTO tblUsrCert (issuerDN, notAfter, notBefore, publicKey, serialNumber, signatureAlgorithm, subjectDN, state)" +
				                                    "VALUES ?, ?, ?, ?, ?, ?, ?, ?;");
		ps.setString(1, issuerDN);
		ps.setString(2, notAfter);
		ps.setString(3, notBefore);
		ps.setString(4, publicKey);
		ps.setString(5, serialNumber);
		ps.setString(6, signatureAlgorithm);
		ps.setString(7, subjectDN);
		ps.setString(8, state);
		ps.executeUpdate();	
		incSerial();
	}
	
	//Aggiorna la scadenza di un certificato
	protected void renewalCert(String serial, String newNotBefore) throws SQLException{
		ResultSet result;
		result = stm.executeQuery("SELECT notBefore FROM tblRinnovi WHERE serialNumeber = '" + serial + "';");
		result.first();
		String oldNotBefore = result.getString(0);
		stm.executeQuery("UPDATE userCertificate SET notBefore = '" + newNotBefore + " WHERE serialNumber = " + serial + "';");
		stm.executeQuery("INSERT INTO  tblRinnovi (data, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "';");
	}
	
	//Setta lo stato di un certificato
	protected void setStateCert(String serial, String state) throws SQLException{
		stm.executeUpdate("UPDATE tblUsrCert SET state = '"+ state +"' WHERE serialNumber = " + serial + "';");
	}
	
	//Restituisce lo stato di un certificato
	protected String getCertState(String serial) throws SQLException {
		ResultSet result = (stm.executeQuery("SELECT state FROM tblUsrCert WHERE serialNumber = '" + serial + ",;"));
		result.first();
		return result.getString(0);
	}
	
	//Inserisce un nuovo utente, da ricontrollare per uniformarlo al DB
	protected void insertUser(String commonName, String organization, String email, String organizationUnit, String locality, String state, String country) throws SQLException{
		stm.executeQuery("INSERT INTO user (user.commonName, user.organization, user.email, user.organizationUnit, user.locality, user.state, user.country) VALUES ('" + commonName + "','" + organization + "','" + organizationUnit + "','" + locality + "','" + state + "','" + country + "');");
		
	}
	
	//Inserisce un nuovo utente del DB
	private boolean insertUser(String subjectDN) throws SQLException{
		if (!userAlreadyExist(subjectDN)){
			stm.executeUpdate("INSERT INTO tblUsers VALUES ('" + subjectDN + "');");
			return true;
		}else{
			return false;
		}	
	}
	
	
}
