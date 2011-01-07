import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import org.bouncycastle.x509.X509V2CRLGenerator;

public class ServerCA extends Thread{
	
	private ServerSocket sSocket;
	private int port;
	private String dbClassName;
	private String dbPath;
	private X509V2CRLGenerator crlGen;
	
	public ServerCA(String dbClassName, String dbPath, int port, X509V2CRLGenerator crlGen) throws IOException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.port = port;
		this.crlGen = crlGen;
		System.out.println("server" + this.port);

	    sSocket  = new ServerSocket(this.port, 900);
	}
	
	public void run(){
		while(true){
			try {
				System.out.println("aspetto la connessione");
				Socket clientConnection = sSocket.accept();
				ServerCAConn caThread = new ServerCAConn(clientConnection, dbClassName, dbPath, crlGen);
				System.out.println("arrivata la connnesone");
				caThread.start();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
