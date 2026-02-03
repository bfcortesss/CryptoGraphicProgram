/**
 * 
 * CS3750 ProjectOne Receiver Program 3
 * By: Brian Flores 
 * 
 */

package Receiver;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {

    // Load YPrivate.key as TWO BigIntegers: n then d
    private static PrivateKey loadPrivateKey(File file) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            Object o1 = ois.readObject();
            Object o2 = ois.readObject();
            if (!(o1 instanceof BigInteger) || !(o2 instanceof BigInteger)) {
                throw new IOException("YPrivate.key is not in expected (n,d) BigInteger format. Re-run KeyGen.");
            }
            BigInteger n = (BigInteger) o1;
            BigInteger d = (BigInteger) o2;
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, d);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        }
    }

    private static String hex(byte[] x){
        StringBuilder sb = new StringBuilder();
        for (byte b: x) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static byte[] sha256File(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f))) {
            byte[] buf = new byte[4096];
            int n; while ((n = bis.read(buf)) != -1) md.update(buf, 0, n);
        }
        return md.digest();
    }

    public static void main(String[] args) {
        try {
            // Load Ky-
            File privFile = new File("../KeyGen/YPrivate.key");
            if (!privFile.exists()) { System.err.println("ERROR: Missing ../KeyGen/YPrivate.key"); return; }
            PrivateKey Ky_minus = loadPrivateKey(privFile);

            // Output filename prompt
            System.out.print("Input the name of the message file: ");
            String outPath = new java.util.Scanner(System.in).nextLine();
            if (outPath == null || outPath.trim().isEmpty()) { System.err.println("ERROR: Output file name required."); return; }
            File outFile = new File(outPath);

            // RSA-decrypt Kxy
            File kxyCipherFile = new File("kxy.rsacipher");
            if (!kxyCipherFile.exists()) { System.err.println("ERROR: Missing kxy.rsacipher"); return; }
            byte[] c1;
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(kxyCipherFile))) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096]; int n; while ((n = bis.read(buf)) != -1) baos.write(buf, 0, n);
                c1 = baos.toByteArray();
            }
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, Ky_minus);
            byte[] Kxy = rsa.doFinal(c1);

            // Build message.kmk prefix with Kxy
            File kmk = new File("message.kmk");
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(kmk))) { bos.write(Kxy); }
            System.out.println("Recovered Kxy (hex): " + hex(Kxy));

            // AES-decrypt message.aescipher
            File aesFile = new File("message.aescipher");
            if (!aesFile.exists()) { System.err.println("ERROR: Missing message.aescipher"); return; }
            SecretKeySpec aesKey = new SecretKeySpec(Kxy, "AES");
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aes.init(Cipher.DECRYPT_MODE, aesKey);

            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(aesFile));
                 BufferedOutputStream msgOut = new BufferedOutputStream(new FileOutputStream(outFile, false));
                 BufferedOutputStream kmkAppend = new BufferedOutputStream(new FileOutputStream(kmk, true))) {
                byte[] inBuf = new byte[16384];
                int n;
                while ((n = bis.read(inBuf)) != -1) {
                    byte[] out = aes.update(inBuf, 0, n);
                    if (out != null) { msgOut.write(out); kmkAppend.write(out); }
                }
                byte[] fin = aes.doFinal();
                if (fin != null) { msgOut.write(fin); kmkAppend.write(fin); }
                kmkAppend.write(Kxy); // finish Kxy || M || Kxy
            }

            // Verify MAC
            File macFile = new File("message.khmac");
            if (!macFile.exists()) { System.err.println("ERROR: Missing message.khmac"); return; }
            byte[] khmac_sender;
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(macFile))) {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096]; int n; while ((n = bis.read(buf)) != -1) baos.write(buf, 0, n);
                khmac_sender = baos.toByteArray();
            }
            byte[] khmac_recv = sha256File(kmk);
            boolean ok = MessageDigest.isEqual(khmac_recv, khmac_sender);
            System.out.println("Received MAC (sender) = " + hex(khmac_sender));
            System.out.println("Recomputed MAC       = " + hex(khmac_recv));
            System.out.println("Authentication " + (ok ? "PASSED" : "FAILED"));
            System.out.println("Decrypted message saved to: " + outFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

