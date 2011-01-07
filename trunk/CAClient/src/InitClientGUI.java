import org.eclipse.swt.widgets.DirectoryDialog;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;


public class InitClientGUI {

	protected Shell shell;
	private Text txtUser;
	private Text txtPass;
	private Text txtHost;
	private Text txtPort;
	private Label lblErr;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			//InitClientGUI window = new InitClientGUI();
			//window.open();
			String dbClassName = "jdbc:sqlite:";
			String dbPath = "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAClient/DataBase/authority.db";
			//String dbPath = dd.open() + "test.db";
			String username = "federico";
			String password = "federico";
			String host = "localhost";
			int port = 8888;
			boolean newUsr = true;
			InitClient client = new InitClient (dbClassName, dbPath, username, password, host, port, newUsr);
			System.out.println(client.recievePubKey());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Open the window.
	 */
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shell.open();
		shell.layout();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shell = new Shell();
		shell.setSize(312, 238);
		shell.setText("SWT Application");
		
		txtUser = new Text(shell, SWT.BORDER);
		txtUser.setBounds(142, 68, 122, 22);
		
		Label lblNomeUtente = new Label(shell, SWT.NONE);
		lblNomeUtente.setBounds(42, 76, 81, 14);
		lblNomeUtente.setText("Nome utente");
		
		Label lblPassword = new Label(shell, SWT.NONE);
		lblPassword.setBounds(42, 104, 54, 14);
		lblPassword.setText("Password");
		
		txtPass = new Text(shell, SWT.BORDER);
		txtPass.setBounds(142, 96, 122, 22);
		
		Label lblHostCa = new Label(shell, SWT.NONE);
		lblHostCa.setBounds(42, 18, 54, 14);
		lblHostCa.setText("Host CA");
		
		txtHost = new Text(shell, SWT.BORDER);
		txtHost.setBounds(142, 10, 122, 22);
		
		Label lblPortaConnessione = new Label(shell, SWT.NONE);
		lblPortaConnessione.setBounds(42, 46, 94, 14);
		lblPortaConnessione.setText("Porta connessione");
		
		txtPort = new Text(shell, SWT.BORDER);
		txtPort.setBounds(142, 38, 122, 22);
		
		Button btnApri = new Button(shell, SWT.NONE);
		btnApri.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				try{
					FileDialog dd = new FileDialog(shell, SWT.OPEN);
					String dbClassName = "jdbc:sqlite:";
					String username = txtUser.getText();
					String dbPath = dd.open();
					String password = txtPass.getText();
					String host = txtHost.getText();
					int port = 8888;
					boolean newUsr = false;
					InitClient client = new InitClient (dbClassName, dbPath, username, password, host, port, newUsr);
					boolean datiOk = client.chekData();
					if (datiOk){
						//Apri un nuovo client
					}else{
						lblErr.setText("Password o dati connessione sbagliati");
					}
				}catch(Exception ex){
					System.out.println(ex.getMessage());
				}
			}
		});
		btnApri.setBounds(68, 144, 76, 24);
		btnApri.setText("Apri...");
		
		Button btnCrea = new Button(shell, SWT.NONE);
		btnCrea.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				try{
					DirectoryDialog dd = new DirectoryDialog(shell, SWT.SAVE);
					String dbClassName = "jdbc:sqlite:";
					String username = txtUser.getText();
					String dbPath = dd.open() + username + ".db";
					String password = txtPass.getText();
					String host = txtHost.getText();
					int port = 8888;
					boolean newUsr = true;
					InitClient client = new InitClient (dbClassName, dbPath, username, password, host, port, newUsr);
					boolean datiOk = client.chekData();
					if (datiOk){
						//Apri un nuovo client
					}else{
						lblErr.setText("Devi cambiare nome o parametri connessione!");
					}
				}catch(Exception ex){
					System.out.println(ex.getMessage());
				}
				
			}
		});
		btnCrea.setBounds(169, 144, 76, 24);
		btnCrea.setText("Crea...");
		
		lblErr = new Label(shell, SWT.NONE);
		lblErr.setBounds(10, 182, 190, 14);

	}
}
