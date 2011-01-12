import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;


public class InitCaGui {

	protected Shell shlInizializzazioneCa;
	private Text textPort;
	private Label lblErr;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			//String dbPath = "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAServer/DataBase/authority.db";
			//int port = 8888;
			//String dbClassName = "jdbc:sqlite:";
			//try {
				//CertificateAuthority ca = new CertificateAuthority(dbClassName, dbPath, port);
			//}catch(Exception e){
				//System.out.println(e.getMessage());
			//System.out.println("Errore nei dati");
			//}
			InitCaGui window = new InitCaGui();
			window.open();
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
		shlInizializzazioneCa.open();
		shlInizializzazioneCa.layout();
		while (!shlInizializzazioneCa.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shlInizializzazioneCa = new Shell();
		shlInizializzazioneCa.setSize(309, 163);
		shlInizializzazioneCa.setText("Inizializzazione CA");
		
		Button btnApri = new Button(shlInizializzazioneCa, SWT.NONE);
		btnApri.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				try{
					FileDialog dialog = new FileDialog(shlInizializzazioneCa, SWT.SAVE);
					String dbPath = dialog.open();
					//dbPath = normalizeUri(dbPath);
					int port = Integer.parseInt(textPort.getText());
					String dbClassName = "jdbc:sqlite:";
					try {
						shlInizializzazioneCa.close();
						@SuppressWarnings("unused")
						CaGui ca = new CaGui(dbClassName, dbPath, port);
					} catch (Exception e1) {
						e1.printStackTrace();
					}
				}catch(Exception e2){
					lblErr.setText("Errore nei dati!!");
				}
				//System.out.println(result);
			}
		});
		btnApri.setBounds(103, 77, 76, 24);
		btnApri.setText("Apri...");
		
		Label lblPortaPerLa = new Label(shlInizializzazioneCa, SWT.NONE);
		lblPortaPerLa.setBounds(10, 28, 135, 14);
		lblPortaPerLa.setText("Porta per la connessione:");
		
		textPort = new Text(shlInizializzazioneCa, SWT.BORDER);
		textPort.setBounds(169, 28, 73, 22);
		
		lblErr = new Label(shlInizializzazioneCa, SWT.NONE);
		lblErr.setBounds(28, 107, 241, 14);

	}
	/**
	private String normalizeUri(String s){
		String result = "";
		StringTokenizer token = new StringTokenizer(s, " ");
		while(token.hasMoreTokens()){
			result += token.nextToken() + "\\ ";
		}
		return result;
		
	}*/
}
