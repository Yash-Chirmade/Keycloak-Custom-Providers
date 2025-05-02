package co.remiges.tech.smsservice.smsgateway;

import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;

import com.webauthn4j.validator.exception.CertificateException;

import java.net.InetSocketAddress;
import java.net.ProxySelector;

// import com.vonage.client.VonageClient;
// import com.vonage.client.sms.SmsSubmissionResponse;
// import com.vonage.client.sms.messages.TextMessage;

// import com.vonage.client.VonageClient;
// import com.vonage.client.sms.MessageStatus;
// import com.vonage.client.sms.SmsSubmissionResponse;
// import com.vonage.client.sms.messages.TextMessage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.cert.X509Certificate;
// import org.jboss.logging.Logger;
/**
 * Sms Service Implementation for sending of SMS
 */
public class SmsServiceImpl implements ISmsService {

	//private static final SnsClient sns = SnsClient.create();

	private static final Logger LOG = Logger.getLogger(SmsServiceImpl.class);
	
	private String senderId;	
	private String apiKey;
	private String apiSecret;
	// private VonageClient client;
	private String feedId;
    private String username;
    private String password;
    private String apiUrl;
    private String proxyHost;
    private int proxyPort;
    private boolean isProxyRequired;
    private String ttl;
    private boolean skipTlsVerification = true; // Set to true to skip TLS verification
    private HttpClient client;
    private HttpRequest request;
	SmsServiceImpl(Map<String, String> config) {
		this.senderId = config.get("smsApiUrl");		
		this.feedId = config.get("feedid");//added 07/10
        this.ttl = config.get("ttl");
        this.username = config.get("username");
        this.password = config.get("password"); 
        this.proxyHost = config.get("proxyHost");
        this.isProxyRequired = Boolean.parseBoolean(config.get("isProxyRequired"));
        this.proxyPort = Integer.parseInt(config.get("proxyPort"));
        this.skipTlsVerification = Boolean.parseBoolean(config.get("skiptls"));
        // this.apiUrl = config.get("apiUrl"); 

		
		LOG.info(String.format("SMS Parameters: Sms api Url<%s>, apiKey<%s>, apiSecret<%s> ttl<%s>",senderId,apiKey,apiSecret,ttl));
		LOG.info(String.format("SMS Parameters: feedId<%s>, username<%s>, Sms api Url<%s>, password<%s>, apiUrl<%s>",feedId,username,senderId,password,apiUrl));
	}

	
	@Override
public void send(String phoneNumber, String message) {
    try {
        LOG.info("Starting sending SMS to phone number: " + phoneNumber);

        String encodedMessage = java.net.URLEncoder.encode(message, java.nio.charset.StandardCharsets.UTF_8.toString());
        String fullUrl = String.format("%s?feedid=%s&text=%s&to=%s&username=%s&senderid=%s&password=%s&short=1",
                senderId, feedId, encodedMessage, phoneNumber, username, senderId, password);

        HttpClient.Builder clientBuilder = HttpClient.newBuilder();

        // Optional TLS verification skipping
       if (skipTlsVerification) {
            LOG.warn("Skipping TLS verification for the HTTP client. This is not recommended for production use.");
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

        // Optional Proxy
        if (isProxyRequired) {
            ProxySelector proxySelector = ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort));
            clientBuilder.proxy(proxySelector);
        }

        HttpClient client = clientBuilder.build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(fullUrl))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200 || response.statusCode() == 202) {
            LOG.info("SMS sent successfully.");
        } else {
            LOG.error("SMS failed with status: " + response.statusCode() + ", response: " + response.body());
        }

    } catch (Exception e) {
        LOG.error("Failed to send SMS: " + e.getMessage(), e);
    }
}



}