
/**
 * 
 * CS3750 ProjectOne KeyGen Program
 * By: Brian Flores
 * 
 */


package KeyGen;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.util.Scanner;

public class KeyGen {

    // Write public key as TWO BigIntegers: n then e
    private static void writePublicKey(File outDir, String filename, RSAPublicKey pub) throws IOException {
        File f = new File(outDir, filename);
        try (ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(f)))) {
            oos.writeObject(pub.getModulus());        // n
            oos.writeObject(pub.getPublicExponent()); // e
        }
    }

    // Write private key as TWO BigIntegers: n then d
    private static void writePrivateKey(File outDir, String filename, RSAPrivateKey priv) throws IOException {
        File f = new File(outDir, filename);
        try (ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(f)))) {
            oos.writeObject(priv.getModulus());         // n
            oos.writeObject(priv.getPrivateExponent()); // d
        }
    }

    public static void main(String[] args) {
        try {
            File outDir = new File(".");
            // 1) Generate two RSA keypairs (X and Y), 1024-bit
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair xKP = kpg.generateKeyPair();
            KeyPair yKP = kpg.generateKeyPair();

            RSAPublicKey xPub = (RSAPublicKey) xKP.getPublic();
            RSAPrivateKey xPriv = (RSAPrivateKey) xKP.getPrivate();
            RSAPublicKey yPub = (RSAPublicKey) yKP.getPublic();
            RSAPrivateKey yPriv = (RSAPrivateKey) yKP.getPrivate();

            // 2) Save as (n,e)/(n,d) BigIntegers
            writePublicKey(outDir,  "XPublic.key",  xPub);
            writePrivateKey(outDir, "XPrivate.key", xPriv);
            writePublicKey(outDir,  "YPublic.key",  yPub);
            writePrivateKey(outDir, "YPrivate.key", yPriv);

            // 3) Prompt for a 16-character AES key (UTF-8)
            System.out.print("Enter a 16-character AES key: ");
            String keyStr = new Scanner(System.in).nextLine();
            if (keyStr == null || keyStr.length() != 16) {
                System.err.println("ERROR: The key must be exactly 16 characters (128 bits UTF-8).");
                return;
            }
            try (Writer w = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("symmetric.key"), StandardCharsets.UTF_8))) {
                w.write(keyStr);
            }

            System.out.println("Generated: XPublic.key, XPrivate.key, YPublic.key, YPrivate.key, symmetric.key");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
