import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.widgets.TabItem;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.DateTime;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.nebula.widgets.datechooser.DateChooser;
import org.eclipse.nebula.widgets.gallery.Gallery;
import org.eclipse.nebula.widgets.gallery.DefaultGalleryItemRenderer;
import org.eclipse.nebula.widgets.gallery.DefaultGalleryGroupRenderer;
import org.eclipse.swt.browser.Browser;


public class ProvaSWT {
	
	

	protected Shell shlCAClient;
	protected Shell shlCaclient2;

	


	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			ProvaSWT window = new ProvaSWT();
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
		shlCAClient.open();
		shlCAClient.layout();
		while (!shlCAClient.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shlCAClient = new Shell();
		shlCAClient.setSize(332, 142);
		shlCAClient.setText("CAClient");
		shlCAClient.setLayout(new GridLayout(5, false));
		new Label(shlCAClient, SWT.NONE);
		
		Label lblScegliUnaOperazione = new Label(shlCAClient, SWT.NONE);
		lblScegliUnaOperazione.setText("SCEGLI UNA OPERAZIONE:");
		new Label(shlCAClient, SWT.NONE);
		new Label(shlCAClient, SWT.NONE);
		new Label(shlCAClient, SWT.NONE);
		new Label(shlCAClient, SWT.NONE);
		
		Label lblCreaUnNuovo = new Label(shlCAClient, SWT.NONE);
		lblCreaUnNuovo.setText("1- Crea un nuovo profilo");
		new Label(shlCAClient, SWT.NONE);
		new Label(shlCAClient, SWT.NONE);
		
		Button btnCrea = new Button(shlCAClient, SWT.NONE);
		btnCrea.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				creaFile();
			}
		});
		btnCrea.setText("Crea...");
		new Label(shlCAClient, SWT.NONE);
		
		Label lblApriUnProfilo = new Label(shlCAClient, SWT.NONE);
		lblApriUnProfilo.setText("2- Apri un profilo già esistente");
		new Label(shlCAClient, SWT.NONE);
		new Label(shlCAClient, SWT.NONE);
		
		Button btnApri = new Button(shlCAClient, SWT.NONE);
		btnApri.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				caricaFile();
			}
		});
		btnApri.setText("Apri...");
	}
		
	private void creaFile(){
		FileDialog dialog = new FileDialog(shlCAClient, SWT.SAVE);
		String result = dialog.open();
	}
	
	private void caricaFile(){
		FileDialog dialog = new FileDialog(shlCAClient, SWT.OPEN);
		String result = dialog.open();
	}
		
		

	
}
