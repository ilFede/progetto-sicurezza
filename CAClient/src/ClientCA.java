import java.io.*;
import java.net.*;

public class ClientCA{
	static int num;
	public int id;
	Socket conn;
	private BufferedReader in;
	private BufferedWriter out;
	
	public ClientCA(){
		id = num;
		num+=1; 
		System.out.println("Il numero è: " + num);
	}
	
	public void getConnection(String host, int port) throws UnknownHostException, IOException{
		Socket conn = new Socket(host, port);
		in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		out = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));	
	}
	
	public void closeConnection() throws IOException{
		in.close();
		out.close();
		conn.close();
	}
	
	public void send (String s) throws IOException{
		out.write("Client " + num + ": ");
		out.write(s);
		out.newLine();
		out.flush();
	}
	
	public void createCert(){
		
	}
	/**public static void main(String args[]) throws UnknownHostException, IOException{
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
		
	}*/
}