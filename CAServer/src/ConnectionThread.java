import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.SQLException;
import java.util.Properties;


public class ConnectionThread extends Thread{
	
	private ServerSocket sSocket;
	private int port;
	private String dbClassName;
	private String dbPath;
	private Properties access;
	
	public ConnectionThread(String dbClassName, String dbPath, int port, Properties access) throws IOException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.port = port;
		this.access = access;
	    sSocket  = new ServerSocket(port);
	}
	
	public void run(){
		while(true){
			try {
				createConnection();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public void createConnection() throws IOException, SQLException{
		Socket clientConnection = sSocket.accept();
		CertificateAuthorityThread caThread = new CertificateAuthorityThread(clientConnection, dbClassName, dbPath, access);
		caThread.start();
	}

}
