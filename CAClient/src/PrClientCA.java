import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;

public class PrClientCA{

	public static void main(String args[]) throws UnknownHostException, IOException{
		ClientCA client = new ClientCA();
		client.getConnection("127.0.0.1", 9999);
		BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("Client " + client.id +  ": ");
		String s = reader.readLine();
		while (!s.equals("stop")){
			client.send(s);
			System.out.print("Client " + client.id +  ": ");
			s = reader.readLine();
		}
		client.closeConnection();
		
	}
}