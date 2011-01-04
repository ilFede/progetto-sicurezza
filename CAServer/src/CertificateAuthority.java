import java.util.*;
import java.util.Date;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.io.*;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V2CRLGenerator;

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
	private final String EXPIRED = "expired";
	private final String CRLSIGNATUREALG = "Mettere l'algoritmo!!!!!";
	private X509V2CRLGenerator crlGen;
	
	//Costruttore, crea connessione e statement per query al DB
	public CertificateAuthority(String dbClassName, String dbPath, int clientConnPort, Properties dbAccess) throws SQLException, ClassNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		super(dbClassName, dbPath, dbAccess);
		this.dbPath = dbPath;
		this.dbAccess = dbAccess;
		this.crlGen = new X509V2CRLGenerator();
		crlGen.setSignatureAlgorithm(CRLSIGNATUREALG);
		//String driver = "jdbc:sqlite:";
		//String dbpath = "jdbc:sqlite:./DataBase/test.db";
	    ckeckCAKey();
	    lunchThrConn(this);
	}
	
	//Avvia il thread per ascoltare le richieste di connessione
	private void lunchThrConn(CertificateAuthority ca) throws IOException{
		ConnectionThread connThr = new ConnectionThread(dbClassName, dbPath, port, dbAccess, crlGen);
		connThr.run();
	}
	
	//Controlla se la CA dispone già di una propria coppia di chiavi controllando il DB
	private void ckeckCAKey() throws SQLException, NoSuchAlgorithmException, InvalidKeySpecException{
		try{
			ResultSet rs = getCAKeyFromDB();
			if (!rs.first()){
				int l=1028;
				createCAKey(l);
			}else{
				getCAKeyFromDB();
			}
		}catch (Exception e){
			System.out.println(e.getMessage());
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
	private void createCAKey(int l) throws NoSuchAlgorithmException, SQLException, CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException, SignatureException{
		KeyPair kp = createKeyPair(l);
		caPrivateKey = kp.getPrivate();
		caPublicKey = kp.getPublic();
		Date notAfter = getDate();
		String notBefore = "2100/31/12";
		String signatureAlgorithm = "RSA";
		String state = "";
		String issuerDN;
		String subjectDN = issuerDN = caDN;
		
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=Test CA Certificate");
		certGen.setSerialNumber(new BigInteger(0 + ""));
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(getDate());
		certGen.setNotAfter(convStringToDate(notBefore));
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(caPublicKey);
		certGen.setSignatureAlgorithm(signatureAlgorithm);

		X509Certificate cert = certGen.generate(caPrivateKey, "BC");
		insertCACert(0 + "", convX509ToBase64(cert), convPrivKeyToBase64(caPrivateKey), convPubKeyToBase64(caPublicKey));
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
	
	//converte una chiave privata in una stringa Base64
	public static String convPrivKeyToBase64(PrivateKey key){
		byte[] tmp = key.getEncoded();
		byte[] conv = Base64.encode(tmp);
		return new String(conv);
	}
	
	//converte una chiave pubblica in una stringa Base64
	public static String convPubKeyToBase64(PublicKey key){
		byte[] tmp = key.getEncoded();
		byte[] conv = Base64.encode(tmp);
		return new String(conv);
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
	
	//Converte unsa Stringa in formato gg/mm/aaaa in util.Date
	protected Date convStringToDate(String s){
		StringTokenizer token = new StringTokenizer(s, "/");
		int day = Integer.parseInt(token.nextToken());
		int month = Integer.parseInt(token.nextToken());
		int year = Integer.parseInt(token.nextToken());
		return new Date (year, month, day);
	}
	/**
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
	}*/
	
	//Converte una certificato in una stringa base 64
	protected String convX509ToBase64(X509Certificate cert){
		try{
			String strCert = new String(cert.getEncoded());
			byte[] byteBase64 = Base64.encode(strCert.getBytes());
			return new String(byteBase64);
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
	//Converte una stringa base64 iu un certificato
	protected X509Certificate convBase64ToX509(String base64Cert){
		try{
			byte[] byteCert = Base64.decode(base64Cert.getBytes());
			CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
			X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(byteCert));
			return cert;
		}catch (Exception e){
			System.out.println(e.getMessage());
			return null;
		}
	}
	
}