import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.StringTokenizer;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.TabFolder;
import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.CTabFolder;
import org.eclipse.swt.widgets.Decorations;
import org.eclipse.swt.widgets.DirectoryDialog;
import org.eclipse.swt.widgets.FileDialog;
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
import org.eclipse.swt.events.MenuDetectListener;
import org.eclipse.swt.events.MenuDetectEvent;


public class ClientCAGui {

	protected Shell shell;
	private Text txtOrRc;
	private Text txtARc;
	private Text txtNewNotBeforeRn;
	private String dbClassName;
	private String dbPath;
	private Socket conn;
	private PublicKey caPk; 
	private ClientCA client;
	private String username;
	private boolean selfSigned = true;
	private boolean haveRenCert = true;
	private boolean haveValidCert = true;
	private boolean utentiOC = false;
	private boolean haveCertOC = false;
	private X509Certificate cert;
	protected final String organizationOID = X509Extensions.IssuerAlternativeName.toString();
	private boolean certSave = false;
	private boolean haveCrl = false;
	private Text txtCrl;
	private X509CRL crl;

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
		shell.setSize(671, 294);
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
		lblValidoDa_1.setBounds(29, 50, 135, 21);
		
		Label lblScadenzaAttuale = new Label(composite_1, SWT.NONE);
		lblScadenzaAttuale.setText("Scadenza attuale:");
		lblScadenzaAttuale.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblScadenzaAttuale.setBounds(29, 77, 135, 21);
		
		Label lblNuovaScadenza = new Label(composite_1, SWT.NONE);
		lblNuovaScadenza.setText("Nuova scadenza (gg/mm/aaaa):");
		lblNuovaScadenza.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblNuovaScadenza.setBounds(29, 104, 207, 21);
		
		final Label lblNotAfterRn = new Label(composite_1, SWT.NONE);
		lblNotAfterRn.setText("Seleziona certificato");
		lblNotAfterRn.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblNotAfterRn.setBounds(241, 50, 135, 21);
		
		final Label lblOldNotBeforeRn = new Label(composite_1, SWT.NONE);
		lblOldNotBeforeRn.setText("Seleziona certificato");
		lblOldNotBeforeRn.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblOldNotBeforeRn.setBounds(241, 77, 135, 21);
		
		final CCombo cmbCertRn = new CCombo(composite_1, SWT.BORDER);
		cmbCertRn.addMenuDetectListener(new MenuDetectListener() {
			public void menuDetected(MenuDetectEvent arg0) {
				System.out.println("dsfdsfdsfsdf");
			}
		});
		cmbCertRn.addSelectionListener(new SelectionAdapter() {
			
			/**public void widgetSelected(SelectionEvent e) {
				if (haveRenCert == true){
					ArrayList<String> array = client.recieveOcsp(cmbCertRn.getText());
					String oldNotBefore = array.get(3);
					String notAfter = array.get(2);
					lblNotAfterRn.setText(notAfter);
					lblOldNotBeforeRn.setText(oldNotBefore);
				}else{
					haveRenCert = false;
				}
				System.out.println("dsfdsfdsfsdf");
			}*/
			@Override
			public void widgetDefaultSelected(SelectionEvent e) {
				System.out.println("dsfdsfdsfsdf");

			}
		});
		cmbCertRn.setBounds(242, 15, 173, 29);
		
		Label lblCertificatoPerLa = new Label(composite_1, SWT.NONE);
		lblCertificatoPerLa.setText("Certificato per la firma:");
		lblCertificatoPerLa.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoPerLa.setBounds(29, 131, 207, 21);
		
		final CCombo cmbSignRn = new CCombo(composite_1, SWT.BORDER);
		cmbSignRn.setBounds(242, 132, 173, 29);
		
		txtNewNotBeforeRn = new Text(composite_1, SWT.BORDER);
		txtNewNotBeforeRn.setBounds(242, 104, 135, 22);
		
		final CCombo cmbLRn = new CCombo(composite_1, SWT.BORDER);
		cmbLRn.setBounds(241, 166, 174, 29);
		
		Button button_1 = new Button(composite_1, SWT.NONE);
		button_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String serialCert = cmbCertRn.getText();
				String serialSign = cmbSignRn.getText();
				String newNotBefore = txtNewNotBeforeRn.getText();
				int l = Integer.parseInt(cmbLRn.getText());
				if ((haveValidCert == true)&&(haveRenCert == true)){
					client.renewsCertificate(serialCert, newNotBefore, serialSign, l);
				}
			}
		});
		button_1.setBounds(29, 206, 76, 24);
		button_1.setText("New Button");
		
		Button button_5 = new Button(composite_1, SWT.NONE);
		button_5.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				haveRenCert = false;
				ArrayList<String> array = client.recieveRenewableCertUsrList(username);
				if (array == null){
					haveRenCert = false;
				}else{
					haveRenCert = true;
					for (int i = 0; i < array.size(); i++){
						cmbCertRn.add(array.get(i));
					}
				}
				ArrayList<String> array2 = client.recieveValidCertUsrList(username);
				if (array2 == null){
					haveValidCert = false;
				}else{
					haveValidCert = true;
					for (int i = 0; i < array.size(); i++){
						cmbSignRn.add(array2.get(i));
					}
				}
				cmbLRn.add("1024");
			}
		});
		button_5.setBounds(478, 20, 76, 24);
		button_5.setText("New Button");
		
		Label lblLunghezzaChiavi = new Label(composite_1, SWT.NONE);
		lblLunghezzaChiavi.setText("Lunghezza chiavi:");
		lblLunghezzaChiavi.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblLunghezzaChiavi.setBounds(29, 166, 207, 21);
		
		Button button_6 = new Button(composite_1, SWT.NONE);
		button_6.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				if (haveRenCert == true){
					ArrayList<String> array = client.recieveOcsp(cmbCertRn.getText());
					String oldNotBefore = array.get(3);
					String notAfter = array.get(2);
					lblNotAfterRn.setText(notAfter);
					lblOldNotBeforeRn.setText(oldNotBefore);
				}else{
					haveRenCert = false;
				}
			}
		});
		button_6.setText("New Button");
		button_6.setBounds(478, 62, 76, 24);
		
		TabItem tabItem_1 = new TabItem(tabFolder, SWT.NONE);
		tabItem_1.setText("New Item");
		
		Composite composite_3 = new Composite(tabFolder, SWT.NONE);
		tabItem_1.setControl(composite_3);
		
		final CCombo cmbUsrListOC = new CCombo(composite_3, SWT.BORDER);
		cmbUsrListOC.setBounds(212, 23, 126, 29);
		
		final CCombo cmbCertListOC = new CCombo(composite_3, SWT.BORDER);
		cmbCertListOC.setBounds(212, 58, 126, 29);
		
		Label lblSelezionaUtente = new Label(composite_3, SWT.NONE);
		lblSelezionaUtente.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblSelezionaUtente.setBounds(30, 23, 131, 29);
		lblSelezionaUtente.setText("Seleziona utente:");
		
		Label lblSelezionaCertificato_1 = new Label(composite_3, SWT.NONE);
		lblSelezionaCertificato_1.setText("Seleziona certificato:");
		lblSelezionaCertificato_1.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		
		final Label lblErrOc = new Label(composite_3, SWT.NONE);
		lblErrOc.setBounds(10, 216, 328, 14);
		lblErrOc.setText("New Label");
		lblSelezionaCertificato_1.setBounds(30, 58, 131, 29);
		
		Button button_7 = new Button(composite_3, SWT.NONE);
		button_7.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				lblErrOc.setText("");
				ArrayList<String> array = client.recieveUrsList();
				utentiOC = false;
				certSave = false;
				cmbUsrListOC.removeAll();
				if (array != null){
					utentiOC = true;
					for (int i = 0; i < array.size(); i++){
						cmbUsrListOC.add(array.get(i));
						utentiOC = true;
					}
				}
			}
		});
		button_7.setBounds(384, 23, 76, 24);
		button_7.setText("New Button");
		
		final Label lblCertOC = new Label(composite_3, SWT.NONE);
		lblCertOC.setText("Seleziona certificato:");
		lblCertOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertOC.setBounds(30, 93, 131, 29);
		
		Button button_8 = new Button(composite_3, SWT.NONE);
		button_8.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				lblCertOC.setText("");
				haveCertOC = false;
				cmbCertListOC.removeAll();
				if (utentiOC == true){
					String user = cmbUsrListOC.getText();
					ArrayList<String> array = client.recieveCertUsrList(user);
					if (array != null){
						haveCertOC = true;
						for (int i = 0; i < array.size(); i++){
							cmbCertListOC.add(array.get(i));
						}
					}else{
						haveCertOC = false;
						lblCertOC.setText("L'utente non ha certificati");
					}
				}
			}
		});
		button_8.setText("New Button");
		button_8.setBounds(384, 58, 76, 24);
		
		final Label lblSerialOC = new Label(composite_3, SWT.NONE);
		lblSerialOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblSerialOC.setBounds(130, 133, 104, 14);
		lblSerialOC.setText("New Label");
		
		final Label lblUserOC = new Label(composite_3, SWT.NONE);
		lblUserOC.setText("New Label");
		lblUserOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblUserOC.setBounds(335, 133, 104, 14);
		
		final Label lblOrgOC = new Label(composite_3, SWT.NONE);
		lblOrgOC.setText("New Label");
		lblOrgOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblOrgOC.setBounds(130, 153, 104, 14);
		
		final Label lblReasonOC = new Label(composite_3, SWT.NONE);
		lblReasonOC.setText("New Label");
		lblReasonOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblReasonOC.setBounds(335, 193, 104, 14);
		
		final Label lblDaOC = new Label(composite_3, SWT.NONE);
		lblDaOC.setText("New Label");
		lblDaOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblDaOC.setBounds(130, 173, 104, 14);
		
		final Label lblAOC = new Label(composite_3, SWT.NONE);
		lblAOC.setText("New Label");
		lblAOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblAOC.setBounds(335, 173, 104, 14);
		
		final Label lblStateOC = new Label(composite_3, SWT.NONE);
		lblStateOC.setText("New Label");
		lblStateOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblStateOC.setBounds(130, 193, 104, 14);
		
		final Label lblSignOC = new Label(composite_3, SWT.NONE);
		lblSignOC.setText("New Label");
		lblSignOC.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblSignOC.setBounds(335, 153, 104, 14);
		
		Button button_9 = new Button(composite_3, SWT.NONE);
		button_9.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				if ((utentiOC == true)&&(haveCertOC == true)){
					String serial = cmbCertListOC.getText();
					ArrayList<String> array = client.recieveOcsp(serial);
					if (array == null){
						lblErrOc.setText("Nessun dato valido dalla CA");
					}else{
						try{
							String certString = array.get(0);
							String state = array.get(1);
							String notAfter = array.get(2);
							String notBefore = array.get(3);
							String serialNumber = array.get(4);
							String subjectDN = array.get(5);
							String reason = array.get(6);
							Date notAft = convStringToDate(notAfter);
							Date notBfr = convStringToDate(notBefore);
							Date now = convStringToDate(getNowStringDate());
							
							cert = convBase64ToX509(certString);
							
							if ((notBfr.compareTo(now) < 1)&&(state.equals("good"))){
								lblStateOC.setText("Scaduto");
							}else if (state.equals("revoked")){
								lblStateOC.setText("Revocato");
								if (reason.equals("0")){
									lblReasonOC.setText("Chiave compromessa");
									//imposta l'etichetta a chiave compromessa
								}else{
									lblReasonOC.setText("Motivo sconosciuto");
									//imposta l'etichetta a motivo sconosciuto
								}
							}
							lblSerialOC.setText(serialNumber);
							lblUserOC.setText(subjectDN);
							lblOrgOC.setText(new String(cert.getExtensionValue(organizationOID)));
							lblDaOC.setText(notBefore);
							lblAOC.setText(notAfter);
							lblSignOC.setText(cert.getSigAlgName());
							certSave = true;
						}catch(Exception ex){
							
						}
						
						/**
						array.add(cert);
						array.add(state);
						array.add(notAfter);
						array.add(notBefore);
						array.add(serialNumber);
						array.add(subjectDN);
						array.add(reason);*/
						
					}
				}
			}
		});
		button_9.setBounds(384, 98, 76, 24);
		button_9.setText("New Button");
		
		Button button_10 = new Button(composite_3, SWT.NONE);
		button_10.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				try{
					if (certSave == true){
						DirectoryDialog dialog = new DirectoryDialog(shell, SWT.SAVE);
						String name = cert.getSerialNumber() + "";
						String path = dialog.open() + "/" +  name + ".cer";
						File file = new File(path);
				        FileOutputStream fosP = new FileOutputStream(file);
				        fosP.write(cert.getEncoded());
				        fosP.close();
					}
				}catch(Exception ex){
					System.out.println(ex.getMessage());
					System.out.println("Impossibile salvare il certificato...");
				}
			}
		});
		button_10.setBounds(475, 163, 76, 24);
		button_10.setText("New Button");
		
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
		
		txtOrRc = new Text(composite, SWT.BORDER);
		txtOrRc.setBounds(158, 43, 204, 22);
		
		txtARc = new Text(composite, SWT.BORDER);
		txtARc.setBounds(158, 98, 125, 22);
		
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
		lblErrRc.setBounds(133, 206, 368, 14);
		
		Button button = new Button(composite, SWT.NONE);
		button.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String notAfter = lblDaRc.getText();
				String notBefore = txtARc.getText();
				String subjectDN = username;
				String signature = cmbAlRc.getText();
				String organizzazionUnit = txtOrRc.getText();
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
		
		
		
		final Label lblHave = new Label(composite, SWT.NONE);
		lblHave.setBounds(327, 169, 274, 14);
		
		Button button_2 = new Button(composite, SWT.NONE);
		button_2.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				lblPropRc.setText(username);
				lblDaRc.setText(getNowStringDate());
				cmbAlRc.add("MD2withRSA");
				cmbAlRc.add("MD5withRSA");
				cmbAlRc.add("SHA1withRSA");
				cmbLRc.add("1024");
				ArrayList<String> array = client.recieveValidCertUsrList(username);
				cmbCerFirRc.removeAll();
				if (array == null){
					selfSigned = true;
					lblHave.setText("Puoi fare solo un SelfSigned");
				}else{
					selfSigned = false;
					lblHave.setText("");
					for (int i = 0; i < array.size(); i++){
						cmbCerFirRc.add(array.get(i));
					}
				}
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
		lblCertificatoDaRevocare.setBounds(38, 79, 161, 16);
		lblCertificatoDaRevocare.setText("Certificato da revocare:");
		
		Label lblMotivazione = new Label(composite_2, SWT.NONE);
		lblMotivazione.setText("Motivazione:");
		lblMotivazione.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblMotivazione.setBounds(38, 114, 161, 16);
		
		Label lblCertificatoPerLa_1 = new Label(composite_2, SWT.NONE);
		lblCertificatoPerLa_1.setText("Certificato per la firma:");
		lblCertificatoPerLa_1.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblCertificatoPerLa_1.setBounds(38, 149, 161, 16);
		
		final CCombo cmbCerRev = new CCombo(composite_2, SWT.BORDER);
		cmbCerRev.setBounds(215, 66, 155, 29);
		
		final CCombo cmbMotRev = new CCombo(composite_2, SWT.BORDER);
		cmbMotRev.setBounds(215, 101, 205, 29);
		
		final CCombo cmbSignRev = new CCombo(composite_2, SWT.BORDER);
		cmbSignRev.setBounds(215, 136, 155, 29);
		
		Label lblEsitRev = new Label(composite_2, SWT.NONE);
		lblEsitRev.setBounds(172, 192, 266, 14);
		lblEsitRev.setText("New Label");
		
		Button button_3 = new Button(composite_2, SWT.NONE);
		button_3.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				String serialCert = cmbCerRev.getText();
				String serialSign = cmbSignRev.getText();
				String mot = cmbMotRev.getText();
				int motiv = 0;
				if ((haveRenCert == true)&&(haveValidCert == true)){
					motiv = 0;
					if (mot.equals("Chiave Compromessa")){
						motiv = 0;
					}else{
						motiv = 1;
					}
					client.sendRevokeRequest(serialCert, motiv, serialSign);
				}
			}
		});
		button_3.setBounds(38, 182, 76, 24);
		button_3.setText("New Button");
		

		final Label lblPuoiRev = new Label(composite_2, SWT.NONE);
		lblPuoiRev.setBounds(413, 151, 161, 14);
		lblPuoiRev.setText("New Label");
		
		final Label lblHaiCert = new Label(composite_2, SWT.NONE);
		lblHaiCert.setText("New Label");
		lblHaiCert.setBounds(413, 66, 161, 14);
		
		final CCombo cmbUsrRev = new CCombo(composite_2, SWT.BORDER);
		cmbUsrRev.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				System.out.println("cioxsad!");
				String serialUser = cmbUsrRev.getText();
				ArrayList<String> array = client.recieveRenewableCertUsrList(serialUser);
				if (array == null){
					haveRenCert = false;
					lblHaiCert.setText("Non hai certificati per continuare");
				}else{
					haveRenCert = true;
					lblHaiCert.setText("");
					cmbCerRev.removeAll();
					for (int i = 0; i < array.size(); i++){
						cmbCerRev.add(array.get(i));
					}
				}
				
			}
		});
		cmbUsrRev.setBounds(215, 32, 155, 29);
		
		Button button_4 = new Button(composite_2, SWT.NONE);
		button_4.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				ArrayList<String> array = client.recieveUrsList();
				System.out.println("Ho i clienti");

				cmbUsrRev.removeAll();
				System.out.println("Ho tolto!!!!");
				for (int i = 0; i < array.size(); i++){
					cmbUsrRev.add(array.get(i));
				}
				
				System.out.println("messo i motivi");
				cmbMotRev.removeAll();
				cmbMotRev.add("Chiave Compromessa");
				cmbMotRev.add("Altro");
				ArrayList<String> array2 = client.recieveValidCertUsrList(username);
				cmbSignRev.removeAll();
				if (array2 == null){
					haveValidCert = false;
					lblPuoiRev.setText("Non hai certificati per continuare");
				}else{
					haveValidCert = true;
					lblPuoiRev.setText("");
					for (int i = 0; i < array2.size(); i++){
						cmbSignRev.add(array2.get(i));
					}
				}
			}
		});
		button_4.setBounds(427, 32, 76, 24);
		button_4.setText("New Button");
		
		Label lblUtente = new Label(composite_2, SWT.NONE);
		lblUtente.setFont(SWTResourceManager.getFont("Ubuntu", 10, SWT.NORMAL));
		lblUtente.setBounds(38, 42, 54, 14);
		lblUtente.setText("Utente:");
		
		TabItem tbtmMostraCrl = new TabItem(tabFolder, SWT.NONE);
		tbtmMostraCrl.setText("Mostra CRL");
		
		TabItem tabItem_2 = new TabItem(tabFolder, SWT.NONE);
		tabItem_2.setText("New Item");
		
		Composite composite_4 = new Composite(tabFolder, SWT.NONE);
		tabItem_2.setControl(composite_4);
		
		Button button_11 = new Button(composite_4, SWT.NONE);
		button_11.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				crl = client.sendCrlRequest();
				txtCrl.setText(crl.toString());
				haveCrl = true;
			}
		});
		button_11.setBounds(10, 10, 76, 24);
		button_11.setText("New Button");
		
		txtCrl = new Text(composite_4, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		txtCrl.setBounds(10, 46, 631, 184);
		
		Button button_12 = new Button(composite_4, SWT.NONE);
		button_12.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				try{
					if (haveCrl == true){
						DirectoryDialog dialog = new DirectoryDialog(shell, SWT.SAVE);
						String name = crl.getThisUpdate() + "";
						String path = dialog.open() + "/" + name + ".cer";
						System.out.println(path);
						File file = new File(path);
						FileOutputStream fosP = new FileOutputStream(file);
						fosP.write(crl.getEncoded());
						fosP.close();
					}
				}catch(Exception ex){
					System.out.println(ex.getMessage());
					System.out.println("Non posso salvare il file...");
				}
			}
		});
		button_12.setBounds(177, 10, 76, 24);
		button_12.setText("New Button");
		
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
	protected static String getNowStringDate(){
		GregorianCalendar gc = new GregorianCalendar();
		String year = ("0" + gc.get(Calendar.YEAR));
		year = year.substring(year.length() - 4, year.length());
		String month = ("0" + gc.get(Calendar.MONTH + 1));
		month = month.substring(month.length() - 2, month.length());
		String day = ("0" + gc.get(Calendar.DAY_OF_MONTH));
		day = day.substring(day.length() - 2, day.length());
		/**String hour = ("0" + gc.get(Calendar.HOUR));
		hour = hour.substring(hour.length() - 2, hour.length());
		String minute = ("0" + gc.get(Calendar.MINUTE));
		minute = minute.substring(minute.length() - 2, minute.length());
		String second = ("0" + gc.get(Calendar.SECOND));
		second = second.substring(second.length() - 2, second.length());*/
		return day + "/" + month + "/" + year;
	}
	
	//Converte unsa Stringa in formato gg/mm/aaaa in util.Date
	@SuppressWarnings("deprecation")
	protected Date convStringToDate(String s){
		StringTokenizer token = new StringTokenizer(s, "/");
		int day = Integer.parseInt(token.nextToken());
		int month = Integer.parseInt(token.nextToken()) - 1;
		int year = Integer.parseInt(token.nextToken()) - 1900;
		return new Date (year, month, day);
	}
	
	//Converte una stringa base64 iu un certificato
	protected X509Certificate convBase64ToX509(String base64Cert) throws CertificateException, NoSuchProviderException{
		byte[] data = Base64.decode(base64Cert);
        CertificateFactory fact = CertificateFactory.getInstance("X.509","BC");
        X509Certificate cert = (X509Certificate)fact.generateCertificate(new ByteArrayInputStream(data));
		return cert;
	}
}
