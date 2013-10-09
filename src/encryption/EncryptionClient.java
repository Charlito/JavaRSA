package encryption;

import java.util.logging.Level;
import java.util.logging.Logger;
import static javax.swing.JOptionPane.*;

/**
 * @author HJ
 */
class EncryptionClient {

    private static Encryption encrypter = new Encryption();

    public static void main(String[] args) throws Exception {
        String[] values = {"512", "1024", "2048", "4096", "8192"};
        int strength = 2048; // Fallback value //

        String selectedValue = "" + showInputDialog(null,
                "Choose encryption strength.\n(2048 recommended)", "Encryption Key Generator",
                INFORMATION_MESSAGE, null, values, values[2]);

        while (selectedValue != null && !selectedValue.equals("")) {
            strength = Integer.parseInt(selectedValue);
            try {
                encrypter.generateKeys(strength);
            } catch (Exception ex) {
                Logger.getLogger(EncryptionClient.class.getName()).log(Level.SEVERE, null, ex);
            }
            String message = showInputDialog(null, "Enter the desired text to be encoded with " + strength + "-bit encryption:");
            byte[] encryptThis = message.getBytes("UTF-8");
            byte[] encrypted = encrypter.rsaEncrypt(encryptThis);
            byte[] decrypted = encrypter.rsaDecrypt(encrypted);
            System.out.println(new String(decrypted, "UTF-8"));
            selectedValue = "" + showInputDialog(null,
                    "Choose encryption strength.\n(2048 recommended)", "Encryption Key Generator",
                    INFORMATION_MESSAGE, null, values, values[2]);
        }
    }
}
