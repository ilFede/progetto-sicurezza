import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;


public class Prove {
	
	public static void main(String args[]) throws NoSuchAlgorithmException{
		//inizializza un generatore di coppie di chiavi usando RSA
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        System.out.print(".");
        // le chiavi sono molto lunghe: 1024 bit sono 128 byte.
        // La forza di RSA è nell'impossibilità pratica di fattorizzare
        // numeri così grandi.
        kpg.initialize(1024);
        System.out.print(".");
        // genera la coppia
        KeyPair kp = kpg.generateKeyPair();
        System.out.print(". Chiavi generate!\n");
        
        // SALVA CHIAVE PUBBLICA
        
        // ottieni la versione codificata in X.509 della chiave pubblica
        // (senza cifrare)
        byte[] publicBytes = kp.getPublic().getEncoded();
        // salva nel keystore selezionato dall'utente
        String p = new String(publicBytes);
        System.out.println("Chiave pubblica: " + p + "/n");
        
        // SALVA CHIAVE PRIVATA
        
        // ottieni la versione codificata in PKCS#8
        byte[] privateBytes = kp.getPrivate().getEncoded();
        p = new String(privateBytes);
        
        System.out.println("Chiave privata: " + p + "/n");
        String ca = kp.getPrivate().getFormat();
        System.out.println("Format: " + ca);
        System.out.println("Le chiavi sono uguali: " + ca.equals(p));

	}

}
