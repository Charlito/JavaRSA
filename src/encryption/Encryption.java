package encryption;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.logging.*;
import javax.crypto.Cipher;

public class Encryption {

    public void generateKeys(int strength) throws Exception {
        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(strength);
            KeyPair kp = kpg.genKeyPair();
            
            // Genererer av noen grunn 65578 om public eksponent ofte //
            
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
            
            saveObjectToFile("public.encryptionKey", pub.getModulus(), pub.getPublicExponent());
            saveObjectToFile("private.encryptionKey", priv.getModulus(), priv.getPrivateExponent());
            savePlainTextToFile("public.txt", pub.getModulus(), pub.getPublicExponent(), strength);
            savePlainTextToFile("private.txt", priv.getModulus(), priv.getPrivateExponent(), strength);

        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void saveObjectToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        FileOutputStream fos = new FileOutputStream(fileName);
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(mod);
            out.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }

    public void savePlainTextToFile(String fileName, BigInteger mod, BigInteger exp, int strength) throws IOException {
        try (FileWriter fw = new FileWriter(fileName, true); PrintWriter pw = new PrintWriter(new BufferedWriter(fw))) {
            pw.println("Modulo-Prime (" + strength + "-bit): " + mod);
            pw.println("Exponent-Prime (" + strength + "-bit): " + exp + "\n");
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }

    public void saveDataAsTextToFile(String fileName, byte[] data) throws IOException {
        try (FileWriter fw = new FileWriter(fileName, true); PrintWriter pw = new PrintWriter(new BufferedWriter(fw))) {
            for (int i = 0; i < data.length; i++) {
                pw.print(data[i]);
            }
            pw.println();
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }

    public void saveDataAsTextToFile(String fileName, String data) throws IOException {
        try (FileWriter fw = new FileWriter(fileName, true); PrintWriter pw = new PrintWriter(new BufferedWriter(fw))) {
            pw.println(data);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }

    PublicKey readPublicKeyFromFile(String keyFileName) throws IOException {
        File file = new File(keyFileName);
        FileInputStream in = new FileInputStream(file);
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) ois.readObject();
            BigInteger e = (BigInteger) ois.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error occurred upon reading the key", e);
        }
    }

    PrivateKey readPrivateKeyFromFile(String keyFileName) throws IOException {
        File file = new File(keyFileName);
        FileInputStream in = new FileInputStream(file);
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(in))) {
            BigInteger m = (BigInteger) ois.readObject();
            BigInteger e = (BigInteger) ois.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fact.generatePrivate(keySpec);
            return privKey;
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error occurred upon reading the key", e);
        }
    }

    public byte[] rsaEncrypt(byte[] data) throws Exception {
        PublicKey pubKey = readPublicKeyFromFile("public.encryptionKey");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherData = cipher.doFinal(data);
        saveDataAsTextToFile("privateData.txt", data);
        return cipherData;
    }

    public byte[] rsaDecrypt(byte[] data) throws Exception {
        PrivateKey privKey = readPrivateKeyFromFile("private.encryptionKey");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] cipherData = cipher.doFinal(data);
        saveDataAsTextToFile("publicData.txt", new String(cipherData, "UTF-8"));
        return cipherData;
    }
//    public static void main(String[] args) {
//        try {
//            /* Creates a 2048-bit encryption generator */
//            Encryption encrypter = new Encryption();
//            encrypter.generateKeys(2048, true);
//            String message = "This is a secret message.";
//            byte[] encryptThis = message.getBytes("UTF-8");
//            byte[] encrypted = encrypter.rsaEncrypt(encryptThis);
//            byte[] decrypted = encrypter.rsaDecrypt(encrypted);
//            System.out.println("Decrypted message: " + new String(decrypted, "UTF-8"));
//        } catch (Exception ex) {
//            Logger.getLogger(Encryption.class.getName()).log(Level.SEVERE, null, ex);
//        }
//
//    }
}
