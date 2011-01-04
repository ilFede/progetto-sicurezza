import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.Properties;

import org.bouncycastle.x509.X509V2CRLGenerator;

public class ConnectionThread extends Thread{
	
	private ServerSocket sSocket;
	private int port;
	private String dbClassName;
	private String dbPath;
	private Properties access;
	private X509V2CRLGenerator crlGen;
	
	public ConnectionThread(String dbClassName, String dbPath, int port, Properties access, X509V2CRLGenerator crlGen) throws IOException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.port = port;
		this.access = access;
		this.crlGen = crlGen;
	    sSocket  = new ServerSocket(this.port);
	}
	
	public void run(){
		while(true){
			try {
				createConnection();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
	}
	
	public void createConnection() throws IOException, SQLException{
		Socket clientConnection = sSocket.accept();
		CertificateAuthorityConn caThread = new CertificateAuthorityConn(clientConnection, dbClassName, dbPath, access, crlGen);
	}

}
