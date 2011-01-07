import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Text;
import org.eclipse.swt.custom.StyledText;


public class MessageWindows {

	protected Shell shlProva;
	private Text text;
	private String title;

	/**
	 * Launch the application.
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			MessageWindows window = new MessageWindows("asdsadsada");
			window.open();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public MessageWindows(String name){
		title = name;
	}

	/**
	 * Open the window.
	 */
	
	public void open() {
		Display display = Display.getDefault();
		createContents();
		shlProva.open();
		shlProva.layout();
		/*/*while (!shlProva.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}*/
	}
	
	public void write(String s){
		text.setText(text.getText() + s);
	}

	/**
	 * Create contents of the window.
	 */
	protected void createContents() {
		shlProva = new Shell();
		shlProva.setSize(450, 300);
		shlProva.setText(title);
		
		text = new Text(shlProva, SWT.MULTI | SWT.WRAP | SWT.V_SCROLL | SWT.BORDER);
		text.setBounds(0, 0, 434, 268);

	}
}
