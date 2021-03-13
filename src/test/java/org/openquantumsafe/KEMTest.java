package org.openquantumsafe;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.stream.Stream;

public class KEMTest {

    private static ArrayList<String> enabled_kems;

    private static String logString = ""; // own

    /**
     * Before running the tests, get a list of enabled KEMs
     */
    @BeforeAll
    public static void init(){
        System.out.println("Initialize list of enabled KEMs");
        enabled_kems = KEMs.get_enabled_KEMs();
    }

    /**
     * Test all enabled KEMs
     */
    @ParameterizedTest(name = "Testing {arguments}")
    @MethodSource("getEnabledKEMsAsStream")
    public void testAllKEMs(String kem_name) throws IOException {
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
        String filename = "KEM_" + kem_name.replaceAll("\\.", "_") + getActualDateReverse() + ".txt";
        printLog("KEM " + kem_name);
        printLog("server PrivateKey size: " + server.export_secret_key().length);
        printLog("server PublicKey size:  " + server.export_public_key().length);
        printLog("clientPublicKey length: " + client_public_key.length + " data: " + bytesToHex(client_public_key));
        printLog("ciphertext length: " + ciphertext.length);
        printLog("ciphertext hex:\n" + bytesToHex(ciphertext));
        printLog("server shared key length: " + shared_secret_server.length + " data: " + bytesToHex(shared_secret_server));
        printLog("client shared key length: " + shared_secret_client.length + " data: " + bytesToHex(shared_secret_client));
        // save data
        Files.write(Paths.get(filename), logString.getBytes(StandardCharsets.UTF_8));
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
