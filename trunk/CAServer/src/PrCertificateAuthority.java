import java.io.IOException;
import java.sql.SQLException;

public class PrCertificateAuthority {
	public static void main(String args[]) throws SQLException, ClassNotFoundException, IOException{
		CertificateAuthority cert = new CertificateAuthority ("CertificateAuthority", "root", "federico");
		while(true){
			System.out.println("Server in attesa di connessione");
			cert.getConnection();
			System.out.println("Mi sono connesso, continuo");
		}
	}
}
