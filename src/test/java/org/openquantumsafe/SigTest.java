package org.openquantumsafe;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.stream.Stream;

public class SigTest {

    private final byte[] message = "This is the message to sign".getBytes();
    private static ArrayList<String> enabled_sigs;

    private static String logString = ""; // own
    private static String algorithmFacts = ""; // own

    /**
     * Before running the tests, get a list of enabled Sigs
     */
    @BeforeAll
    public static void init(){
        System.out.println("Initialize list of enabled Signatures");
        enabled_sigs = Sigs.get_enabled_sigs();
    }

    /**
     * Test all enabled Sigs
     */
    @ParameterizedTest(name = "Testing {arguments}")
    @MethodSource("getEnabledSigsAsStream")
    public void testAllSigs(String sig_name) throws IOException {

        // just 1 run
        //if (sig_name.contentEquals("SIG_Dilithium2")) {
            StringBuilder sb = new StringBuilder();
            sb.append(sig_name);
            sb.append(String.format("%1$" + (40 - sig_name.length()) + "s", ""));
            // Create signer and verifier
            Signature signer = new Signature(sig_name);
            Signature verifier = new Signature(sig_name);
            // Generate signer key pair
            byte[] signer_public_key = signer.generate_keypair();
            // Sign the message
            byte[] signature = signer.sign(message);
            // Verify the signature
            boolean is_valid = verifier.verify(message, signature, signer_public_key);
            assertTrue(is_valid, sig_name);
            // If successful print Sig name, otherwise an exception will be thrown
            sb.append("\033[0;32m").append("PASSED").append("\033[0m");
            System.out.println(sb.toString());
            // own functions
            logString = "";
            String filename = "SIG_" + sig_name.replaceAll("\\.", "_") + "_" + getActualDateReverse() + ".txt";
            //printLog("SIG " + sig_name);
            printLog("SIG");
            printLog(sig_name);
            printLog("***********************************");
            printLog("signer PrivateKey size: " + signer.export_secret_key().length);
            printLog("signer PublicKey size:  " + signer.export_public_key().length);
            printLog("signerPublicKey length: " + signer_public_key.length + " data: " + bytesToHex(signer_public_key));
            printLog("***********************************");
            printLog("signature length: " + signature.length);
            printLog("signature hex:\n" + bytesToHex(signature));
            printLog("signature valid: " + is_valid);
            // save data
            Files.write(Paths.get(filename), logString.getBytes(StandardCharsets.UTF_8));

            // algorithmFacts kem | name | private key length | public key length | signature length
            algorithmFacts = algorithmFacts + "| key exchange (KEM) | " + sig_name + " | "
                + signer.export_secret_key().length + " | " + signer.export_public_key()
                + " | " + signature.length + " |";
        filename = "KEM_" + sig_name.replaceAll("\\.", "_") + "_" + getActualDateReverse() + "_af.txt";
        Files.write(Paths.get(filename), algorithmFacts.getBytes(StandardCharsets.UTF_8));
        //}
    }

    /**
     * Test the MechanismNotSupported Exception
     */
    @Test
    public void testUnsupportedSigExpectedException() {
        Assertions.assertThrows(MechanismNotSupportedError.class, () -> new Signature("MechanismNotSupported"));
    }

    /**
     * Method to convert the list of Sigs to a stream for input to testAllSigs
     */
    private static Stream<String> getEnabledSigsAsStream() {
        return enabled_sigs.parallelStream();
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
