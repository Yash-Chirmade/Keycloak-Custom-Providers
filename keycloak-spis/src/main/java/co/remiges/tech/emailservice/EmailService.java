package co.remiges.tech.emailservice;

import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;

import com.webauthn4j.validator.exception.CertificateException;

public class EmailService {

    private static final Logger LOG = Logger.getLogger(EmailService.class);

    public EmailResponse sendEmailWithoutProxy(String recipient, String subject, String content, String apiKey, String apiUrl) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    .header("api_key", apiKey)
                    .POST(BodyPublishers.ofString(createEmailPayload(recipient, subject, content)))
                    .build();

            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

            if (response.statusCode() == 200 || response.statusCode() == 202) {
                LOG.info("Email sent successfully with status code: " + response.statusCode());
                return new EmailResponse(true, "");
            } else {
                String errorMessage = "Email failed with status code: " + response.statusCode() + " and error: " + response.body();
                LOG.error(errorMessage);
                return new EmailResponse(false, errorMessage);
            }
        } catch (Exception e) {
            String errorMessage = "Failed to send email: " + e.getMessage();
            LOG.error(errorMessage, e);
            return new EmailResponse(false, errorMessage);
        }
    }

    public EmailResponse sendEmailWithProxy(
        String recipient, String subject, String content, String apiKey, String apiUrl, 
        String proxyHost, String proxyPort, boolean skipTlsVerification) {
    try {
        // Initialize HttpClient builder
        HttpClient.Builder clientBuilder = HttpClient.newBuilder();

        // Skip TLS verification if specified
        if (skipTlsVerification) {
            try {
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, new TrustManager[]{
                        new X509TrustManager() {
                            @Override
                            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                // No validation for client certificates
                            }
                
                            @Override
                            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                // No validation for server certificates
                            }
                
                            @Override
                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0]; // Return an empty array
                            }
                        }
                }, new java.security.SecureRandom());
                
                clientBuilder.sslContext(sslContext)
                             .sslParameters(new SSLParameters());
            } catch (Exception e) {
                LOG.error("Failed to configure SSL context for skipping TLS verification. Falling back to default settings.", e);
                // Proceed with default TLS settings
            }
        }

        // Configure proxy settings
        ProxySelector proxySelector = ProxySelector.of(new InetSocketAddress(proxyHost, Integer.parseInt(proxyPort)));
        clientBuilder.proxy(proxySelector);

        // Build the HttpClient
        HttpClient client = clientBuilder.build();

        // Prepare the HTTP request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .header("Content-Type", "application/json")
                .header("api_key", apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(createEmailPayload(recipient, subject, content)))
                .build();

        // Send the HTTP request
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        // Log response body for debugging purposes
        LOG.info(response.body());

        // Process response
        if (response.statusCode() == 200 || response.statusCode() == 202) {
            LOG.info("Email sent successfully with status code: " + response.statusCode());
            return new EmailResponse(true, "");
        } else {
            String errorMessage = "Email failed with status code: " + response.statusCode() + " and error: " + response.body();
            LOG.error(errorMessage);
            return new EmailResponse(false, errorMessage);
        }
    } catch (Exception e) {
        // Handle any unexpected exceptions
        String errorMessage = "Failed to send email: " + e.getMessage();
        LOG.error(errorMessage, e);
        return new EmailResponse(false, errorMessage);
    }
}
    

    private String createEmailPayload(String recipient, String subject, String content) {
        return String.format("{\"personalizations\":[{\"recipient\":\"%s\"}],\"from\":{\"fromEmail\":\"bsestarmf@bseindia.com\",\"fromName\":\"BSE StArmf\"},\"subject\":\"%s\",\"content\":\"%s\",\"tags\":\"Bse StArmf\"}", recipient, subject, content);
    }

    public static class EmailResponse {
        private final boolean success;
        private final String errorMessage;

        public EmailResponse(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }
}
