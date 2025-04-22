package co.remiges.tech.smsservice.smsgateway;

import java.util.Map;

import org.jboss.logging.Logger;

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
        // this.apiUrl = config.get("apiUrl"); 

		
		LOG.info(String.format("SMS Parameters: SenderID<%s>, apiKey<%s>, apiSecret<%s> ttl<%s>",senderId,apiKey,apiSecret,ttl));
		LOG.info(String.format("SMS Parameters: feedId<%s>, username<%s>, senderId<%s>, password<%s>, apiUrl<%s>",feedId,username,senderId,password,apiUrl));
	}

	
	@Override
    public void send(String phoneNumber, String message) {
        try {
			LOG.info("Starting sending sms to phone number: " + phoneNumber);
            String encodedMessage = java.net.URLEncoder.encode(message, java.nio.charset.StandardCharsets.UTF_8.toString());
            String fullUrl = String.format("%s?feedid=%s&text=%s&to=%s&username=%s&senderid=%s&password=%s&short=1",
                                           senderId, feedId, encodedMessage, phoneNumber, username, senderId, password);

            if (isProxyRequired) {
            ProxySelector proxySelector = ProxySelector.of(new InetSocketAddress(proxyHost, proxyPort));
            client = HttpClient.newBuilder()
                .proxy(proxySelector)
                .build();
            }else{
                client = HttpClient.newHttpClient();
            }
           
            request = HttpRequest.newBuilder()
            .uri(URI.create(fullUrl))
            .GET()  
            .build();
            
            HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

            if ((response.statusCode() == 200) || (response.statusCode() == 202)) {
                LOG.info("Message sent successfully.");
            } else {
                LOG.error("Message failed with error: " + response.body());
            }
        } catch (Exception e) {
            LOG.error("Failed to send SMS" + e.getMessage(), e);
        }
    }


}