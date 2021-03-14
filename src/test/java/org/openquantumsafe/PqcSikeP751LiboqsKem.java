package org.openquantumsafe;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class PqcSikeP751LiboqsKem {
    private static String logString = "";
    public static void main(String[] args) throws IOException {
        logString = "";
        String kemName = "Sike-p751";
        String filename = "PQC Sike-p751 KEM" + getActualDateReverse();

        String printString = "PQC Sike key encapsulation mechanism (KEM) with Liboqs";
        System.out.println(printString);
        printLog(printString);

        printString = "\nThis is an example for a key encapsulation mechanism (KEM)";
        System.out.println(printString);
        printLog(printString);
        printString = "using the algorithm Sike 751 and the PQC library";
        System.out.println(printString);
        printLog(printString);
        printString = "from OpenQuantumSafe.org - liboqs-java";
        System.out.println(printString);
        printLog(printString);

        printString = "\ngenerate a key pair for client=receiver and server=sender";
        System.out.println(printString);
        printLog(printString);
        KeyEncapsulation client = new KeyEncapsulation(kemName);
        KeyEncapsulation server = new KeyEncapsulation(kemName);

        // save the keys as byte array, here shown for server
        byte[] serverPrivateKeyEncoded = server.export_secret_key();
        byte[] serverPublicKeyEncoded = server.export_public_key();
        printString = "generated private key length: " + serverPrivateKeyEncoded.length;
        System.out.println(printString);
        printLog(printString);
        printString = "generated public key length:  " + serverPublicKeyEncoded.length;
        System.out.println(printString);
        printLog(printString);
        // save the keys to file
        Files.write(Paths.get(filename + ".server.privatekey"), serverPrivateKeyEncoded);
        Files.write(Paths.get(filename + ".server.publickey"), serverPublicKeyEncoded);
        Files.write(Paths.get(filename + ".client.privatekey"), client.export_secret_key());
        Files.write(Paths.get(filename + ".server.publickey"), client.export_public_key());
        printString = "private and public key from server and client saved to file "
            + filename + ".extension";
        System.out.println(printString);
        printLog(printString);

        // the client generates a public key and sends it to the sender
        byte[] clientPublicKey = client.generate_keypair();
        printString = "length of the received clientPublicKey: " + clientPublicKey.length;
        System.out.println(printString);
        printLog(printString);

        // the sender generates his shared secret
        printString = "\n* * * generate the keyToEncrypt with the public key of the recipient * * *";
        System.out.println(printString);
        printLog(printString);
        // Server: encapsulate secret with client's public key
        Pair<byte[], byte[]> server_pair = server.encap_secret(clientPublicKey);
        byte[] encryptedKey = server_pair.getLeft(); // send to recipient along with the ciphertext
        printString = "encryptedKey length: " + encryptedKey.length + " data: " + bytesToHex(encryptedKey);
        byte[] sharedSecretServer = server_pair.getRight();
        System.out.println("sharedSecretServer length: " + sharedSecretServer.length + " data: "
                + bytesToHex(sharedSecretServer));

        printString = "\n* * * decapsulate the keyToEncrypt with the private key of the recipient * * *";
        System.out.println(printString);
        printLog(printString);
        // Client: decapsulate
        byte[] sharedSecretClient = client.decap_secret(encryptedKey);
        printString = "sharedSecretClient length: " + sharedSecretClient.length + " data: "
                + bytesToHex(sharedSecretClient);
        System.out.println(printString);
        printLog(printString);

        // save logString to file
        Files.write(Paths.get(filename + ".txt"), logString.getBytes(StandardCharsets.UTF_8));

    }
    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private static String getActualDateReverse() {
        // provides the actual date and time in this format yyyy-MM-dd_HH-mm-ss e.g. 2020-03-16_10-27-15
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        LocalDateTime today = LocalDateTime.now();
        return formatter.format(today);
    }

    private static void printLog(String string) {
        logString = logString + string + "\n";
    }
}
