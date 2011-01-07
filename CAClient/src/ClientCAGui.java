import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.GregorianCalendar;

import org.bouncycastle.util.encoders.Base64;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.widgets.TabItem;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import com.swtdesigner.SWTResourceManager;
import org.eclipse.swt.widgets.List;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.custom.CCombo;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Tree;
import org.eclipse.swt.events.DisposeListener;
import org.eclipse.swt.events.DisposeEvent;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;


public class ClientCAGui {

	protected Shell shell;
	private Text lblOrRc;
	private Text lblARc;
	private Text text_2;
	private String dbClassName;
	private String dbPath;
	private Socket conn;
	private PublicKey caPk; 
	private ClientCA client;
	private String username;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			PublicKey pk = convBase64ToPubKey("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQzQax6keAVJSpitc9erRNIVtNWdlUnQ8Mm0Z0H4a+Cz2G4HDLvkYjmIhkKW0Li/a3ZnaN73tfGAa1wSFG/99kiwc4+c4mCttpP/Zwdq7ovX1KQX4bjGYO8cPZRBcocZoHDvq8xBS8yyENIJXE4VKHFLh8iMbXKnBBUZT82m4dZOMwIDAQAB");
			String username = "federico";
			String dbPath = "/home/federico/Scienze Informatiche/Sicurezza/Progetto/Workspace/CAClient/DataBase/authority.db";
			String dbClassName = "jdbc:sqlite:";
			Socket conn = new Socket ("localhost", 8888);
			ClientCAGui window = new ClientCAGui(username, dbClassName, dbPath, conn, pk);
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public ClientCAGui (String username, String dbClassName, String dbPath, Socket conn, PublicKey caPk) throws SQLException, ClassNotFoundException{
		this.dbClassName = dbClassName;
		this.dbPath = dbPath;
		this.conn = conn;
		this.caPk = caPk;
		this.username = username;
		client = new ClientCA(this.username, this.dbClassName, this.dbPath, this.conn, this.caPk);
		
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
		shell.setSize(671, 291);
		shell.setText("SWT Application");
		
		TabFolder tabFolder = new TabFolder(shell, SWT.NONE);
		tabFolder.setBounds(0, 0, 655, 268);
		
		TabItem tbtmRichiestaCertificato = new TabItem(tabFolder, SWT.NONE);
		tbtmRichiestaCertificato.addDisposeListener(new DisposeListener() {
			public void widgetDisposed(DisposeEvent arg0) {
				
			}
		});
		tbtmRichiestaCertificato.setText("Richiesta certificato");
		
		TabItem tbtmRinnovaCertificato = new TabItem(tabFolder, SWT.NONE);
		tbtmRinnovaCertificato.setText("Rinnova certificato");
		
		Composite composite_1 = new Composite(tabFolder, SWT.NONE);
		tbtmRinnovaCertificato.setControl(composite_1);
		
		Label lblSelezionaCertificato = new Label(composite_1, SWT.NONE);
		lblSelezionaCertificato.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblSelezionaCertificato.setBounds(29, 23, 207, 21);
		lblSelezionaCertificato.setText("Certificato da rinnovare:");
		
		Label lblValidoDa_1 = new Label(composite_1, SWT.NONE);
		lblValidoDa_1.setText("Valido da:");
		lblValidoDa_1.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblValidoDa_1.setBounds(29, 60, 135, 21);
		
		Label lblScadenzaAttuale = new Label(composite_1, SWT.NONE);
		lblScadenzaAttuale.setText("Scadenza attuale:");
		lblScadenzaAttuale.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblScadenzaAttuale.setBounds(29, 87, 135, 21);
		
		Label lblNuovaScadenza = new Label(composite_1, SWT.NONE);
		lblNuovaScadenza.setText("Nuova scadenza (gg/mm/aaaa):");
		lblNuovaScadenza.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblNuovaScadenza.setBounds(29, 114, 207, 21);
		
		Label lblACnotBefore = new Label(composite_1, SWT.NONE);
		lblACnotBefore.setText("Seleziona certificato");
		lblACnotBefore.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblACnotBefore.setBounds(241, 60, 135, 21);
		
		Label lblACnotBeforeOld = new Label(composite_1, SWT.NONE);
		lblACnotBeforeOld.setText("Seleziona certificato");
		lblACnotBeforeOld.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblACnotBeforeOld.setBounds(241, 87, 135, 21);
		
		CCombo combo_1 = new CCombo(composite_1, SWT.BORDER);
		combo_1.setBounds(242, 15, 173, 29);
		
		Label lblCertificatoPerLa = new Label(composite_1, SWT.NONE);
		lblCertificatoPerLa.setText("Certificato per la firma:");
		lblCertificatoPerLa.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoPerLa.setBounds(29, 141, 207, 21);
		
		CCombo combo_6 = new CCombo(composite_1, SWT.BORDER);
		combo_6.setBounds(241, 141, 173, 29);
		
		text_2 = new Text(composite_1, SWT.BORDER);
		text_2.setBounds(242, 114, 135, 22);
		
		Button button_1 = new Button(composite_1, SWT.NONE);
		button_1.setBounds(29, 189, 76, 24);
		button_1.setText("New Button");
		
		TabItem tabItem = new TabItem(tabFolder, SWT.NONE);
		tabItem.setText("New Item");
		
		Composite composite = new Composite(tabFolder, SWT.NONE);
		tabItem.setControl(composite);
		
		Label lblOrganizzazione = new Label(composite, SWT.NONE);
		lblOrganizzazione.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblOrganizzazione.setBounds(26, 43, 113, 22);
		lblOrganizzazione.setText("Organizzazione:");
		
		Label lblValidoFinoA = new Label(composite, SWT.NONE);
		lblValidoFinoA.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblValidoFinoA.setBounds(26, 98, 78, 14);
		lblValidoFinoA.setText("Valido fino a:");
		
		Label lblAlgoritmoDiFirma = new Label(composite, SWT.NONE);
		lblAlgoritmoDiFirma.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblAlgoritmoDiFirma.setBounds(26, 134, 133, 22);
		lblAlgoritmoDiFirma.setText("Algoritmo di firma:");
		
		lblOrRc = new Text(composite, SWT.BORDER);
		lblOrRc.setBounds(158, 43, 204, 22);
		
		lblARc = new Text(composite, SWT.BORDER);
		lblARc.setBounds(158, 98, 125, 22);
		
		final CCombo cmbAlRc = new CCombo(composite, SWT.BORDER);
		cmbAlRc.setBounds(158, 127, 144, 29);
		
		Label lblValidoDa = new Label(composite, SWT.NONE);
		lblValidoDa.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblValidoDa.setBounds(26, 71, 66, 26);
		lblValidoDa.setText("Valido da:");
		
		Label lblProprietario = new Label(composite, SWT.NONE);
		lblProprietario.setText("Proprietario:");
		lblProprietario.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblProprietario.setBounds(26, 15, 113, 22);
		
		final Label lblPropRc = new Label(composite, SWT.NONE);
		lblPropRc.setText("Proprietario");
		lblPropRc.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblPropRc.setBounds(158, 15, 113, 22);
		
		final Label lblDaRc = new Label(composite, SWT.NONE);
		lblDaRc.setText("Valido da");
		lblDaRc.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblDaRc.setBounds(158, 71, 66, 26);
		
		final CCombo cmbLRc = new CCombo(composite, SWT.BORDER);
		cmbLRc.setBounds(457, 127, 144, 29);
		
		final CCombo cmbCerFirRc = new CCombo(composite, SWT.BORDER);
		cmbCerFirRc.setBounds(158, 162, 144, 29);
		
		final Label lblErrRc = new Label(composite, SWT.NONE);
		lblErrRc.setBounds(126, 216, 204, 14);
		
		Button button = new Button(composite, SWT.NONE);
		button.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String notAfter = lblDaRc.getText();
				String notBefore = lblARc.getText();
				String subjectDN = username;
				String signature = cmbAlRc.getText();
				String organizzazionUnit = lblOrRc.getText();
				String serialCert = cmbCerFirRc.getText(); 
				int l = Integer.parseInt(cmbLRc.getText());
				try{
					if (serialCert.equals("")){
						boolean b = client.certificateSSRequest(notAfter, notBefore, subjectDN, signature, organizzazionUnit, l);
					}else{
						boolean b = client.certificateRequest(notAfter, notBefore, subjectDN, signature, organizzazionUnit, l, serialCert);
					}
				}catch (Exception ex){
					lblErrRc.setText("Errore!!");
				}
			}
		});
		button.setBounds(26, 206, 76, 24);
		button.setText("New Button");
		
		Label lblCertificatoPerFirma = new Label(composite, SWT.NONE);
		lblCertificatoPerFirma.setText("Certificato per firma:");
		lblCertificatoPerFirma.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoPerFirma.setBounds(26, 169, 133, 22);
		
		
		
		Label label_2 = new Label(composite, SWT.NONE);
		label_2.setBounds(327, 169, 144, 14);
		label_2.setText("New Label");
		
		Button button_2 = new Button(composite, SWT.NONE);
		button_2.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				lblPropRc.setText(username);
				lblDaRc.setText(getStringDate());
				cmbAlRc.add("MD2withRSA");
				cmbAlRc.add("MD5withRSA");
				cmbAlRc.add("SHA1withRSA");
				cmbLRc.add("1024");
				//Mettere il controllo selfsigned
			}
		});
		button_2.setBounds(425, 15, 76, 24);
		button_2.setText("New Button");
		
		Label lblLunghezzaChiave = new Label(composite, SWT.NONE);
		lblLunghezzaChiave.setText("Lunghezza chiave:");
		lblLunghezzaChiave.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblLunghezzaChiave.setBounds(327, 134, 133, 22);
		
		
		
		TabItem tbtmRevocaCertificato = new TabItem(tabFolder, SWT.NONE);
		tbtmRevocaCertificato.setText("Revoca Certificato");
		
		Composite composite_2 = new Composite(tabFolder, SWT.NONE);
		tbtmRevocaCertificato.setControl(composite_2);
		
		Label lblCertificatoDaRevocare = new Label(composite_2, SWT.NONE);
		lblCertificatoDaRevocare.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoDaRevocare.setBounds(38, 27, 161, 16);
		lblCertificatoDaRevocare.setText("Certificato da revocare:");
		
		Label lblMotivazione = new Label(composite_2, SWT.NONE);
		lblMotivazione.setText("Motivazione:");
		lblMotivazione.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblMotivazione.setBounds(38, 59, 161, 16);
		
		Label lblCertificatoPerLa_1 = new Label(composite_2, SWT.NONE);
		lblCertificatoPerLa_1.setText("Certificato per la firma:");
		lblCertificatoPerLa_1.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoPerLa_1.setBounds(38, 106, 161, 16);
		
		CCombo combo_3 = new CCombo(composite_2, SWT.BORDER);
		combo_3.setBounds(215, 27, 155, 29);
		
		CCombo combo_4 = new CCombo(composite_2, SWT.BORDER);
		combo_4.setBounds(215, 59, 155, 29);
		
		CCombo combo_5 = new CCombo(composite_2, SWT.BORDER);
		combo_5.setBounds(215, 106, 155, 29);
		
		TabItem tbtmMostraCrl = new TabItem(tabFolder, SWT.NONE);
		tbtmMostraCrl.setText("Mostra CRL");
		
		TabItem tbtmMostraCertificatoocsp = new TabItem(tabFolder, SWT.NONE);
		tbtmMostraCertificatoocsp.setText("Mostra Certificato (OCSP)");

	}
	//Converte una stringa BASE64 in una chiave pubblica
	protected static PublicKey convBase64ToPubKey(String publicKey) throws InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] publicKeyBytes =  Base64.decode(publicKey);
		X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}
	
	//Restituisce la data attuale nel formato gg/mm/aaaa
	protected static String getStringDate(){
		GregorianCalendar gc = new GregorianCalendar();
		String year = ("0" + gc.get(Calendar.YEAR));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + gc.get(Calendar.MONTH));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + gc.get(Calendar.DAY_OF_MONTH));
		day = day.substring(day.length() - 2, day.length());
		String hour = ("0" + gc.get(Calendar.HOUR));
		hour = hour.substring(hour.length() - 2, hour.length());
		String minute = ("0" + gc.get(Calendar.MINUTE));
		minute = minute.substring(minute.length() - 2, minute.length());
		String second = ("0" + gc.get(Calendar.SECOND));
		second = second.substring(second.length() - 2, second.length());
		return year + "/" + month + "/" + day;
	}
}
