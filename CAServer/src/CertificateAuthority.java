import java.util.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.io.*;

public class CertificateAuthority {
	
	private Connection conn;
	private Statement stm;
	private int port;
	private String dbClassName;
	private String dbPath;
	private String dbUsername;
	private String dbPassword;
	private Properties access;
	private PrivateKey caPrivateKey;
	private PublicKey caPublicKey;
	private int lastSerial; //primp seriale non usato, viene salvato in una cella del DB
	private String caDN = "FedeCA";
	private final String GOOD = "good";
	private final String REVOKED = "revoked";
	private final String UNKNOWN = "unknown";
	
	//Costruttore, crea connessione e statement per query
	public CertificateAuthority(String dbClassName, String dbPath, int port, String dbUsername, String dbPassword) throws SQLException, ClassNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.port = port;
		this.dbUsername = dbUsername;
		this.dbPassword = dbPassword;
		//String driver = "jdbc:sqlite:";
		//String dbpath = "jdbc:sqlite:./DataBase/test.db";
	    Class.forName(dbClassName);
	    access = new Properties();
	    access.put("user", dbUsername);
	    access.put("password", dbPassword);
	    conn = (DriverManager.getConnection(this.dbClassName + this.dbPath, access));
	    stm = conn.createStatement();
	    ckeckCAKey();
	    lunchThrConn(this);
	}
	
	//Avvia il thread per ascoltare le richieste di connessione
	private void lunchThrConn(CertificateAuthority ca) throws IOException{
		ConnectionThread connThr = new ConnectionThread(dbClassName, dbPath, port, access);
		connThr.run();
	}
	
	//Controlla se la CA dispone già di una propria coppia di chiavi controllando il DB
	private void ckeckCAKey() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblCACert;");
		if (!rs.first()){
			int l=1028;
			createCAKey(l);
		}else{
			getCAKeyToDB();
		}
	}
	
	//Genera una coppia di chiavi pubblica/privata
	private KeyPair createKeyPair(int l) throws NoSuchAlgorithmException{
		//inizializza un generatore di coppie di chiavi usando RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(l);
        // genera la coppia
        KeyPair kp = kpg.generateKeyPair();
        return kp;
	}
	
	//Crea le chiavi della CA e le inserisce nel DB
	private void createCAKey(int l) throws NoSuchAlgorithmException, SQLException{
		KeyPair kp = createKeyPair(l);
		caPrivateKey = kp.getPrivate();
		caPublicKey = kp.getPublic();
		String notAfter = getDate();
		String notBefore = "2100/31/12 23:59:59";
		String signatureAlgorithm = "RSA";
		String state = "";
		String issuerDN;
		String subjectDN = issuerDN = caDN;
		insertCACert(issuerDN, notAfter, notBefore, convPrivKeyToString(caPrivateKey), conPubKeyToString(caPublicKey), signatureAlgorithm, subjectDN, state);
	}
	
	//Interroga il DB per ottenere le chiavi della CA
	private void getCAKeyToDB() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		ResultSet rs = stm.executeQuery("SELECT privateKey, publicKey FROM tblCACert WHERE state = '" + GOOD +"';");
		rs.first();
		caPrivateKey = convStringToPrivKey(rs.getString("privateKey"));
		caPublicKey = convStringToPubKey(rs.getString("publicKey"));		
	}
	
	//Converte una stringa in una chiave pubblica
	private PublicKey convStringToPubKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] publicKeyBytes = publicKey.getBytes();
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
	}
	
	//Converte una string in una chiave privata
	private PrivateKey convStringToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] privateKeyBytes = privateKey.getBytes();
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
	}
	
	//converte una chiave privata in una stringa
	private String convPrivKeyToString(PrivateKey key){
		return new String(key.getEncoded());
	}
	
	//converte una chiave pubblica in una stringa
	private String conPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}
	
	//Ottiene l'ultimo seriale usato dalla tabella del DB
	private void getSerialToDB() throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSeriale");
		if (rs.first()){
			lastSerial = rs.getInt("serial");
		}else{
			lastSerial = 1;
		}
	}
	
	//Imposta l'ultimo seriale usato nella tabella del BD
	private void setSerialInDB(int newSerial) throws SQLException{
		ResultSet rs = stm.executeQuery("SELECT * FROM tblSerial;");
		if (rs.first()){
			stm.executeUpdate("UPDATE tblSeriale SET serial = " + newSerial + ";");
		}else{
			stm.executeUpdate("INSERT INTO tblSeriale VALUES (1);");
		}
	}
	
	//Restituisce il primo seriale disponibile
	private int getSerial(){
		return lastSerial;
	}
	
	//Incrementa il numero seriale usato per i nuovi certificati
	private void incSerial() throws SQLException{
		getSerial();
		lastSerial += 1;
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
	
	//Inserisce un nuovo record nei certifiati della CA
	public void insertCACert(String issuerDN, String notAfter, String notBefore, String privateKey, String publicKey, String signatureAlgorithm, String subjectDN, String state) throws SQLException{
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
	public void insertUsrCert(String issuerDN, String notAfter, String notBefore, String publicKey, String signatureAlgorithm, String subjectDN, String state) throws SQLException{
		String serialNumber = getSerial() + "";
		PreparedStatement ps=conn.prepareStatement( "INSERT INTO tblUsrCert (issuerDN, notAfter, notBefore, publicKey, serialNumber, signatureAlgorithm, subjectDN, state)" +
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
	public void renewalCert(String serial, String newNotBefore) throws SQLException{
		ResultSet result;
		result = stm.executeQuery("SELECT notBefore FROM tblRinnovi WHERE serialNumeber = '" + serial + "';");
		result.first();
		String oldNotBefore = result.getString(0);
		stm.executeQuery("UPDATE userCertificate SET notBefore = '" + newNotBefore + " WHERE serialNumber = " + serial + "';");
		stm.executeQuery("INSERT INTO  tblRinnovi (data, serialNumber, oldNotBefore, newNotBefore) VALUES ('" + getDate() + "','"+ serial + "','" + oldNotBefore + "','" + newNotBefore + "';");
	}
	
	//Setta lo stato i un certificato
	public void setStateCert(String serial, String state) throws SQLException{
		stm.executeUpdate("UPDATE tblUsrCert SET state = '"+ state +"' WHERE serialNumber = " + serial + "';");
	}
	
	//Restituisce lo stato di un certificato
	public String getCertState(String serial) throws SQLException {
		ResultSet result = (stm.executeQuery("SELECT state FROM tblUsrCert WHERE userCertificate.id = '" + serial + ",;"));
		result.first();
		return result.getString(0);
	}
	
	//Inserisce un nuovo utente, da ricontrollare per uniformarlo al DB
	public void insertUser(String commonName, String organization, String email, String organizationUnit, String locality, String state, String country) throws SQLException{
		stm.executeQuery("INSERT INTO user (user.commonName, user.organization, user.email, user.organizationUnit, user.locality, user.state, user.country) VALUES ('" + commonName + "','" + organization + "','" + organizationUnit + "','" + locality + "','" + state + "','" + country + "');");
		
	}
	
	
}