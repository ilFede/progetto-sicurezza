import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
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


public class DBQuery {
	
	private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
	private Properties dbAccess;
	private int lastSerial; //primo seriale non usato, viene salvato in una cella del DB
	private final String GOOD = "good";
	private final String REVOKED = "revoked";
	private final String EXPIRED = "expired";
	
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
	
	protected int getFreeSerial() throws SQLException{
		int serial = getSerial() + 1;
		incSerial();
		return serial;
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
	
	//Restituisce la lista degli utenti della CA
	protected ResultSet getCAUser() throws SQLException{
		return stm.executeQuery("SELECT subjecDN from tblUsers;" );
	}
	
	//Restituisce tutti i certificati validi di un utente
	protected ResultSet getUserValidCert(String user) throws SQLException{
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE state = 'good' AND issuerDN = '" + user + "';" );
	}
	
	//Restituisce tutti i certificati di un utente
	protected ResultSet getUserCert(String user) throws SQLException{
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN FROM tblUsrCert WHERE issuerDN = '" + user + "';" );
	}
	
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
	
	//Restituisce i certificati della CA
	protected ResultSet getCAKeyFromDB() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		return stm.executeQuery("SELECT privateKey, publicKey, cert FROM tblCACert");	
	}
	
	//Inserisce un nuovo record nei certifiati della CA
	protected void insertCACert(String serial, String privKey, String pubKey, String cert) throws SQLException{
		stm.executeUpdate("INSERT INTO tblCACert (serialNumber, privateKey, publicKey, cert) VALUES + '" + serial + "', '" + privKey + ", '" + pubKey + "', '" + cert + "';");
	}
	
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
	
	//Restituisce un certificato
	protected ResultSet getUsrCert(String serial) throws SQLException{
		return stm.executeQuery("SELECT cert, state, notAfter, notBefore, serialNumber, subjectDN WHERE serial = '" + serial +"';");	
	}
	
	//Restituisce il certificato della CA
	protected ResultSet getCACert(String serial) throws SQLException{
		return stm.executeQuery("SELECT cert FROM tblCACert;");	
	}
	
	//Inserisce un nuovo certificato tra quelli degli utenti
	protected void insertUsrCert(String cert, int state, String notAfter, String notBefore, String serialNumber, String subjectDN) throws SQLException{
		PreparedStatement ps = conn.prepareStatement( "INSERT INTO tblUsrCert (cert, state, notAfter, notBefore, serialNumber, subjectDN)" +
				                                    "VALUES ?, ?, ?, ?, ?, ?;");
		ps.setString(1, cert);
		ps.setInt(2, state);
		ps.setString(3, notAfter);
		ps.setString(4, notBefore);
		ps.setString(5, serialNumber);
		ps.setString(6, subjectDN);
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
		stm.executeQuery("INSERT INTO  tblRinnovi (data, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getStringDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "';");
	}
	
	//Restituisce la lista dei certificati revocati
	protected ResultSet getRevokedCert() throws SQLException{
		return stm.executeQuery("SELECT serialNumber FROM tblUsrCert WHERE state = '" + REVOKED + "';");
	}
	
	
	//Setta lo stato di un certificato
	protected void setStateCert(String serial, String state, int reason) throws SQLException{
		stm.executeUpdate("UPDATE tblUsrCert SET state = '"+ state +"' AND reason = '" + reason + "' WHERE serialNumber = " + serial + "';");
	}
	
	//Restituisce lo stato di un certificato
	protected String getCertState(String serial) throws SQLException {
		ResultSet result = (stm.executeQuery("SELECT state FROM tblUsrCert WHERE serialNumber = '" + serial + ",;"));
		result.first();
		return result.getString(0);
	}
	
	/**
	//Inserisce un nuovo utente, da ricontrollare per uniformarlo al DB
	protected void insertUser(String commonName, String organization, String email, String organizationUnit, String locality, String state, String country) throws SQLException{
		stm.executeQuery("INSERT INTO user (user.commonName, user.organization, user.email, user.organizationUnit, user.locality, user.state, user.country) VALUES ('" + commonName + "','" + organization + "','" + organizationUnit + "','" + locality + "','" + state + "','" + country + "');");
		
	}
	*/
	
	//Inserisce un nuovo utente nel DB
	protected boolean insertUser(String subjectDN) throws SQLException{
		if (!userAlreadyExist(subjectDN)){
			stm.executeUpdate("INSERT INTO tblUsers VALUES ('" + subjectDN + "');");
			return true;
		}else{
			return false;
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
	
	//Converte un Date in formato gg/mm/aaaa
	protected String getStringDate(Date date){
		String year = ("0" + date.getYear());
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + date.getMonth());
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + date.getDay());
		day = day.substring(day.length() - 2, day.length());
		return day + "/" + month + "/" + year;
	}
	
	
}
