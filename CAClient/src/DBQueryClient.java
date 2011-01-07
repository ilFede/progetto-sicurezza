import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;


public class DBQueryClient {
	
	private Statement stm;
	private Connection conn;
	private String dbClassName;
	private String dbPath;
	//private int fistFreeSerial; //primo seriale non usato, viene salvato in una cella del DB
	//private final String GOOD = "good";
	//private final String REVOKED = "revoked";
	//private final String EXPIRED = "expired";
	
	public DBQueryClient(String dbClassName, String dbPath) throws SQLException, ClassNotFoundException {
		Class.forName("org.sqlite.JDBC"); 
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		conn = (DriverManager.getConnection(this.dbClassName + this.dbPath));
	    stm = conn.createStatement();
	}
	
	//Restituisce il nome dell'utente
	protected ResultSet getUsername() throws SQLException{
		return stm.executeQuery("SELECT username FROM tblUsr;");
	}
	
	//Restituisce la password dell'utente
	protected ResultSet getPassword() throws SQLException{
		return stm.executeQuery("SELECT password FROM tblUsr;");
	}
	
	//Restituisce la chiave privata di un cxertificato
	protected ResultSet getPrivKeyToDB(String serial) throws SQLException{
		return stm.executeQuery("SELECT privateKey FROM tblUsrCert WHERE serial = '" + serial + "';");
	}
	
	//Inserisce un nuovo certificato nel DB
	protected void insertUsrCert(String serial, String pubKey, String privKey, String cert) throws SQLException{
		stm.executeUpdate("INSERT INTO tblUsrCert(serialNumber, publicKey, privateKey) VALUES '" + serial + "', '" + pubKey + "', '" + privKey + "', '" + cert + "';");
	}
	
	//Metodo che inizializza il db
	protected void inizializeDb() throws SQLException{
		stm.executeUpdate("DROP TABLE IF EXISTS tblUsrCert;");
		stm.executeUpdate("DROP TABLE IF EXISTS tblUsr;");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsrCert (cert TEXT, privateKey TEXT, publicKey TEXT, serialNumber TEXT);");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsr (password TEXT, subjectDN TEXT);");
		stm.executeUpdate("CREATE TABLE IF NOT EXISTS tblUsrCert (cert TEXT, privateKey TEXT, publicKey TEXT, serialNumber TEXT);");
	}
	
	//Metodo che inserisce l'utente nel db
	protected void insertUser(String user, String password) throws SQLException{
		stm.executeUpdate("INSERT INTO tblUsr (subjectDN, password) VALUES ('" + user + "', '" + password + "');");
	}
	
	//Metodo che restituisce le credenziali di accesso
	protected ResultSet getLogin() throws SQLException{
		return stm.executeQuery("SELECT subjectDN, password FROM tblUsr");
	}
}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	