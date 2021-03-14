package org.openquantumsafe;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class KEMTest2 {

    private static ArrayList<String> enabled_kems;

    private static String logString = ""; // own

    /**
     * Before running the tests, get a list of enabled KEMs
     */
    @BeforeAll
    public static void init(){
        System.out.println("Initialize list of enabled KEMs OWN");
        enabled_kems = KEMs.get_enabled_KEMs();
    }

    /**
     * Test all enabled KEMs
     */
    @ParameterizedTest(name = "Testing {arguments}")
    @MethodSource("getEnabledKEMsAsStream")
    public void testAllKEMs(String kem_name) throws IOException {

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

        /*
        StringBuilder sb = new StringBuilder();
        sb.append(kem_name);
        sb.append(String.format("%1$" + (40 - kem_name.length()) + "s", ""));

        // Create client and server
        KeyEncapsulation client = new KeyEncapsulation(kem_name);
        KeyEncapsulation server = new KeyEncapsulation(kem_name);

        // Generate client key pair
        byte[] client_public_key = client.generate_keypair();

        // Server: encapsulate secret with client's public key
        Pair<byte[], byte[]> server_pair = server.encap_secret(client_public_key);
        byte[] ciphertext = server_pair.getLeft();
        byte[] shared_secret_server = server_pair.getRight();

        // Client: decapsulate
        byte[] shared_secret_client = client.decap_secret(ciphertext);

        // Check if equal
        assertArrayEquals(shared_secret_client, shared_secret_server, kem_name);

        // If successful print KEM name, otherwise an exception will be thrown
        sb.append("\033[0;32m").append("PASSED").append("\033[0m");
        System.out.println(sb.toString());

        // own functions
        logString = "";
        String filename = "KEM_" + kem_name.replaceAll("\\.", "_") + "_" + getActualDateReverse() + ".txt";
        printLog("KEM");
        printLog(kem_name);
        printLog("***********************************");
        printLog("server PrivateKey size: " + server.export_secret_key().length);
        printLog("server PublicKey size:  " + server.export_public_key().length);
        printLog("clientPublicKey length: " + client_public_key.length + " data: " + bytesToHex(client_public_key));
        printLog("***********************************");
        printLog("ciphertext to share");
        printLog("ciphertext length: " + ciphertext.length);
        printLog("ciphertext hex:\n" + bytesToHex(ciphertext));
        printLog("***********************************");
        printLog("shared key for both parties");
        printLog("server shared key length: " + shared_secret_server.length + " data: " + bytesToHex(shared_secret_server));
        printLog("client shared key length: " + shared_secret_client.length + " data: " + bytesToHex(shared_secret_client));
        // save data
        Files.write(Paths.get(filename), logString.getBytes(StandardCharsets.UTF_8));

         */
    }

    /**
     * Test the MechanismNotSupported Exception
     */
    @Test
    public void testUnsupportedKEMExpectedException() {
        Assertions.assertThrows(MechanismNotSupportedError.class, () -> new KeyEncapsulation("MechanismNotSupported"));
    }

    /**
     * Method to convert the list of KEMs to a stream for input to testAllKEMs
     */
    private static Stream<String> getEnabledKEMsAsStream() {
        return enabled_kems.parallelStream();
    }

    // ********** own methods ***********

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
