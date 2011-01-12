import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;


public class ServerSWT {

	protected Shell shlConnessioneCa;
	private Text dbName;
	private Text dbPort;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			ServerSWT window = new ServerSWT();
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
		shlConnessioneCa.open();
		shlConnessioneCa.layout();
		while (!shlConnessioneCa.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shlConnessioneCa = new Shell();
		shlConnessioneCa.setSize(376, 183);
		shlConnessioneCa.setText("CONNESSIONE CA");
		shlConnessioneCa.setLayout(new GridLayout(2, false));
		new Label(shlConnessioneCa, SWT.NONE);
		
		Label lblParametriConnessione = new Label(shlConnessioneCa, SWT.NONE);
		lblParametriConnessione.setText("PARAMETRI DI CONNESSIONE:");
		new Label(shlConnessioneCa, SWT.NONE);
		new Label(shlConnessioneCa, SWT.NONE);
		
		Label lblNomeDatabase = new Label(shlConnessioneCa, SWT.NONE);
		lblNomeDatabase.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblNomeDatabase.setText("Nome database:");
		
		dbName = new Text(shlConnessioneCa, SWT.BORDER);
		dbName.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		
		Label lblPorta = new Label(shlConnessioneCa, SWT.NONE);
		lblPorta.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, false, false, 1, 1));
		lblPorta.setText("Porta:");
		
		dbPort = new Text(shlConnessioneCa, SWT.BORDER);
		dbPort.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 1, 1));
		new Label(shlConnessioneCa, SWT.NONE);
		
		Button btnConnetti = new Button(shlConnessioneCa, SWT.NONE);
		btnConnetti.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				avviaServer();
			}
		});
		btnConnetti.setText("Connetti!");
	}
		
	public void avviaServer(){
		//Completare avvio server CA
	}

}
