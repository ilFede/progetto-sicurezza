import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.custom.CTabItem;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;


public class CaGui {

	protected Shell shell;
	private Text txtCert;
	private CertificateAuthority ca;
	private Text txtRen;
	private Text txtRin;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		/**try {
			CaGui window = new CaGui();
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
		String dbPath = "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAServer/DataBase/authority.db";
		int port = 8888;
		String dbClassName = "jdbc:sqlite:";
		try {
			// ca = new CertificateAuthority(dbClassName, dbPath, port);
		}catch(Exception e){
			System.out.println(e.getMessage());
		System.out.println("Errore nei dati");
		}*/
	}

	/**
	 * Open the window.
	 */
	
	public CaGui(String dbClassName, String dbPath, int port){
		try{
			//String dbPath = "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAServer/DataBase/authority.db";
			//int port = 8888;
			//String dbClassName = "jdbc:sqlite:";
		    ca = new CertificateAuthority(dbClassName, dbPath, port);
			open();
		}catch (Exception e){
			System.out.println(e.getMessage());
		}
	}
	/**
	 * @wbp.parser.entryPoint
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
		shell.setSize(535, 300);
		shell.setText("Server CA");
		
		Composite composite = new Composite(shell, SWT.NONE);
		composite.setBounds(0, 0, 519, 268);
		
		CTabFolder tabFolder = new CTabFolder(composite, SWT.BORDER);
		tabFolder.setBounds(0, 0, 519, 268);
		tabFolder.setSelectionBackground(Display.getCurrent().getSystemColor(SWT.COLOR_TITLE_INACTIVE_BACKGROUND_GRADIENT));
		
		CTabItem tbtmCertificati = new CTabItem(tabFolder, SWT.NONE);
		tbtmCertificati.setText("Certificati");
		
		Composite composite_1 = new Composite(tabFolder, SWT.NONE);
		tbtmCertificati.setControl(composite_1);
		
		Button btnCarica_2 = new Button(composite_1, SWT.NONE);
		btnCarica_2.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				txtCert.setText(ca.getUsrCert());
			}
		});
		btnCarica_2.setBounds(10, 10, 76, 24);
		btnCarica_2.setText("Carica");
		
		txtCert = new Text(composite_1, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		txtCert.setBounds(10, 40, 503, 204);
		
		CTabItem tbtmRinnovi = new CTabItem(tabFolder, SWT.NONE);
		tbtmRinnovi.setText("Rinnovi");
		
		Composite composite_2 = new Composite(tabFolder, SWT.NONE);
		tbtmRinnovi.setControl(composite_2);
		
		txtRen = new Text(composite_2, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		txtRen.setBounds(0, 40, 513, 204);
		
		Button btnCarica_1 = new Button(composite_2, SWT.NONE);
		btnCarica_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				txtRen.setText(ca.getRenew());
			}
		});
		btnCarica_1.setBounds(0, 10, 76, 24);
		btnCarica_1.setText("Carica");
		
		CTabItem tbtmRevoche = new CTabItem(tabFolder, SWT.NONE);
		tbtmRevoche.setText("Revoche");
		
		Composite composite_3 = new Composite(tabFolder, SWT.NONE);
		tbtmRevoche.setControl(composite_3);
		
		txtRin = new Text(composite_3, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		txtRin.setBounds(0, 52, 513, 192);
		
		Button btnCarica = new Button(composite_3, SWT.NONE);
		btnCarica.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				txtRin.setText(ca.getRevoked());
			}
		});
		btnCarica.setBounds(0, 10, 76, 24);
		btnCarica.setText("Carica");

	}
}
