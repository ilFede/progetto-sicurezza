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

public class CertificateAuthority extends DBQuery {
	
	private String dbClassName;
	private Properties dbAccess;
	private String dbPath;
	private int port;
	private PrivateKey caPrivateKey;
	private PublicKey caPublicKey;
	private String caDN = "FedeCA";
	private final String GOOD = "good";
	private final String REVOKED = "revoked";
	private final String UNKNOWN = "unknown";
	
	//Costruttore, crea connessione e statement per query al DB
	public CertificateAuthority(String dbClassName, String dbPath, int clientConnPort, Properties dbAccess) throws SQLException, ClassNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		super(dbClassName, dbPath, dbAccess);
		this.dbPath = dbPath;
		this.dbAccess = dbAccess;
		//String driver = "jdbc:sqlite:";
		//String dbpath = "jdbc:sqlite:./DataBase/test.db";
	    ckeckCAKey();
	    lunchThrConn(this);
	}
	
	//Avvia il thread per ascoltare le richieste di connessione
	private void lunchThrConn(CertificateAuthority ca) throws IOException{
		ConnectionThread connThr = new ConnectionThread(dbClassName, dbPath, port, dbAccess);
		connThr.run();
	}
	
	//Controlla se la CA dispone già di una propria coppia di chiavi controllando il DB
	private void ckeckCAKey() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		ResultSet rs = getCAKeyFromDB();
		if (!rs.first()){
			int l=1028;
			createCAKey(l);
		}else{
			getCAKeyFromDB();
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
		insertCACert(issuerDN, notAfter, notBefore, convPrivKeyToString(caPrivateKey), convPubKeyToString(caPublicKey), signatureAlgorithm, subjectDN, state);
	}
	
	//Converte una stringa in una chiave pubblica
	private static PublicKey convStringToPubKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] publicKeyBytes = publicKey.getBytes();
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(ks);
	}
	
	//Converte una stringa in una chiave privata, da controllare
	public static PrivateKey convStringToPrivKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] privateKeyBytes = privateKey.getBytes();
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privateKeyBytes);
	    KeyFactory kf = KeyFactory.getInstance("RSA");
	    return kf.generatePrivate(ks); 
	}
	
	//converte una chiave privata in una stringa
	public static String convPrivKeyToString(PrivateKey key){
		return new String(key.getEncoded());
	}
	
	//converte una chiave pubblica in una stringa
	private static String convPubKeyToString(PublicKey key){
		return new String(key.getEncoded());
	}
	
	
	
	//Restituisce la data attuale nel forato AAAA/M/GG HH:MM:SS
	private String getDate(){
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