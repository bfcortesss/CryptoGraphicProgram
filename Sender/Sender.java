
/**
 * 
 * CS3750 ProjectOne Sender Program 2
 * By: Brian Flores
 * 
 */

package Sender;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class Sender {

    // Load YPublic.key as TWO BigIntegers: n then e
    private static PublicKey loadPublicKey(File file) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            Object o1 = ois.readObject();
            Object o2 = ois.readObject();
            if (!(o1 instanceof BigInteger) || !(o2 instanceof BigInteger)) {
                throw new IOException("YPublic.key is not in expected (n,e) BigInteger format. Re-run KeyGen.");
            }
            BigInteger n = (BigInteger) o1;
            BigInteger e = (BigInteger) o2;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        }
    }

    private static byte[] readAll(File f) throws IOException {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f))) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n; while ((n = bis.read(buf)) != -1) baos.write(buf, 0, n);
            return baos.toByteArray();
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
            // Load Ky+
            File pubFile = new File("../KeyGen/YPublic.key");
            if (!pubFile.exists()) { System.err.println("ERROR: Missing ../KeyGen/YPublic.key"); return; }
            PublicKey Ky_plus = loadPublicKey(pubFile);

            // Load Kxy
            File symFile = new File("../KeyGen/symmetric.key");
            if (!symFile.exists()) { System.err.println("ERROR: Missing ../KeyGen/symmetric.key"); return; }
            String kxyStr = new String(readAll(symFile), StandardCharsets.UTF_8);
            if (kxyStr.length() != 16) { System.err.println("ERROR: symmetric.key must be exactly 16 characters; length=" + kxyStr.length()); return; }
            byte[] Kxy = kxyStr.getBytes(StandardCharsets.UTF_8);

            // Input message file
            System.out.print("Input the name of the message file: ");
            String msgPath = new java.util.Scanner(System.in).nextLine();
            File msgFile = new File(msgPath);
            if (!msgFile.exists()) { System.err.println("ERROR: Message file not found: " + msgFile.getAbsolutePath()); return; }

            // Build message.kmk = Kxy || M || Kxy
            File kmk = new File("message.kmk");
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(kmk));
                 BufferedInputStream  bis = new BufferedInputStream(new FileInputStream(msgFile))) {
                bos.write(Kxy);
                byte[] buf = new byte[8192];
                int n; while ((n = bis.read(buf)) != -1) bos.write(buf, 0, n);
                bos.write(Kxy);
            }

            // MAC = SHA256(message.kmk)
            byte[] mac = sha256File(kmk);
            System.out.print("Do you want to invert the 1st byte in SHA256(Kxy||M||Kxy)? (Y or N): ");
            String ans = new java.util.Scanner(System.in).nextLine().trim();
            if (!ans.isEmpty() && (ans.charAt(0) == 'Y' || ans.charAt(0) == 'y')) mac[0] = (byte) (~mac[0]);
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.khmac"))) { bos.write(mac); }
            System.out.println("Keyed Hash MAC (SHA-256) = " + hex(mac));

            // AES encrypt M
            SecretKeySpec aesKey = new SecretKeySpec(Kxy, "AES");
            Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aes.init(Cipher.ENCRYPT_MODE, aesKey);
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(msgFile));
                 BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("message.aescipher"))) {
                byte[] inBuf = new byte[16384];
                int n;
                while ((n = bis.read(inBuf)) != -1) {
                    byte[] out = aes.update(inBuf, 0, n);
                    if (out != null) bos.write(out);
                }
                byte[] fin = aes.doFinal(); if (fin != null) bos.write(fin);
            }

            // RSA wrap Kxy
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, Ky_plus);
            byte[] kxyCipher = rsa.doFinal(Kxy);
            try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("kxy.rsacipher"))) { bos.write(kxyCipher); }

            System.out.println("Wrote files: message.kmk, message.khmac, message.aescipher, kxy.rsacipher");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

