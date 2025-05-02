package co.remiges.tech.captchaservice;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import co.remiges.tech.Constants;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;


public class CaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {

    private static final Logger logger = Logger.getLogger(CaptchaUsernamePasswordForm.class);

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        form.setAttribute("captchaRequired", true);
        return super.createLoginForm(form);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        if (logger.isInfoEnabled()) {
            logger.info("validateRecaptcha(AuthenticationFlowContext) - Before the validation");
        }
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("action(AuthenticationFlowContext) - start");
    
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    
        // 🔐 Decryption Section
        String encryptedDataHex = formData.getFirst("data");
        String saltHex = formData.getFirst("s");
    
        // logger.debug("Encrypted data: " + encryptedData);
        // logger.debug("AES key (s): " + secretKey);
    
        if (encryptedDataHex != null && saltHex != null) {
            try {
                byte[] encryptedBytes = hexToBytes(encryptedDataHex);
                byte[] saltBytes = hexToBytes(saltHex);
        
                // ✅ 16-byte zero IV
                byte[] ivBytes = new byte[16];
        
                // Derive key from password + salt
                String password = "secretPassword";
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, 100000, 256);
                SecretKey tmp = factory.generateSecret(spec);
                SecretKeySpec keySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
        
                // AES-GCM decryption
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(128, ivBytes);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        
                byte[] decrypted = cipher.doFinal(encryptedBytes);
                String json = new String(decrypted, StandardCharsets.UTF_8);
        
                logger.debug("Decrypted JSON: " + json);
        
                Map<String, String> decryptedMap = JsonSerialization.readValue(json, Map.class);
                decryptedMap.forEach((key, value) -> {
                    formData.putSingle(key, value);
                    logger.info("Injected decrypted field: " + key + " = " + value);
                });
        
            } catch (Exception e) {
                logger.error("AES-GCM decryption failed", e);
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                return;
            }
        } else {
            logger.warn("Encrypted payload or key missing. Skipping decryption.");
        }
    
        // 🔐 CAPTCHA section
        boolean success = false;
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String incorrectCaptchaMsg = captchaConfig.getConfig().get(Constants.INCORRECT_CAPTCHA_MSG);
        String captcha = formData.getFirst("user_captcha");
        String captchaSecret = formData.getFirst("captcha_secret");
        UserLoginFailureProvider user = context.getSession().loginFailures();
    
        logger.debug("captcha: " + captcha);
        logger.debug("captcha_secret: " + captchaSecret);
    
        if (!Validation.isBlank(captcha)) {
            success = validateRecaptcha(context, success, captcha, captchaSecret);
        }
        if (success) {
            logger.info("CAPTCHA validation passed. Proceeding with standard authentication.");
            super.action(context);
        } else {
            logger.warn("CAPTCHA validation failed.");
            context.form().setAttribute("captchaError", true);
            Response challengeResponse = challenge(context, incorrectCaptchaMsg, "CAPTCHA_INPUT");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }
    
        logger.debug("action(AuthenticationFlowContext) - end");
    }
    

    protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha,
            String captchaSecret) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        try {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String validateCaptchaAPI = captchaConfig.getConfig().get(Constants.VALIDATE_CAPTCHA_API);
            HttpPost post = new HttpPost(validateCaptchaAPI);
            logger.info("captcha:: " + captcha);
            logger.info("captcha secret:: " + captchaSecret);
            post.setHeader("Content-Type", "application/json");
            String jsonPayload = String.format("{\"data\": { \"captcha\":\"%s\", \"captcha_id\":\"%s\" }}", captcha,
                    captchaSecret);
            logger.info("Sending CAPTCHA validation payload: " + jsonPayload);
            post.setEntity(new StringEntity(jsonPayload, "UTF8"));
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                logger.debug("CAPTCHA validation response: " + json);
                Object success_resp = json.get("status");
                if (success_resp != null && success_resp.equals("success")) {
                    success = Boolean.TRUE;
                }
            } finally {
                content.close();
            }
        } catch (Exception e) {
            logger.error("Exception occurred during CAPTCHA validation", e);
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }
 
    // Convert hex to byte array
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
