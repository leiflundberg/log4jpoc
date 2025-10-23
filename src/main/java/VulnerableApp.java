import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;

public class VulnerableApp {
    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public static void main(String[] args) {
        System.out.println("Starting VulnerableApp...");
        System.err.println("Starting VulnerableApp (stderr)...");

        try {
            ServerSocket serverSocket = new ServerSocket(8080);
            System.out.println("Vulnerable server listening on port 8080");
            System.err.println("Vulnerable server listening on port 8080 (stderr)");
            System.out.flush();
            System.err.flush();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                BufferedReader in = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream()));

                String inputLine = in.readLine();
                System.out.println("Received: " + inputLine);

                // VULNERABLE: Logging user input directly in format string
                // Using {} placeholder is SAFE, concatenation is VULNERABLE
                logger.error("Request: " + inputLine);

                clientSocket.getOutputStream().write("OK\n".getBytes());
                clientSocket.close();
            }
        } catch (Exception e) {
            System.err.println("ERROR: Exception occurred!");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
