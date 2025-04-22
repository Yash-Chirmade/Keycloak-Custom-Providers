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
import java.util.*;

public class CaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator{

	private static final Logger logger = Logger.getLogger(CaptchaUsernamePasswordForm.class);

	@Override
	protected Response createLoginForm( LoginFormsProvider form ) {
		form.setAttribute("captchaRequired", true);
		return super.createLoginForm( form );
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
		if (logger.isInfoEnabled()) {
			logger.info(
					"validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
		}
		
		super.authenticate(context);
	}
	
	

	@Override
	public void action(AuthenticationFlowContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - start");
		}
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		boolean success = false;
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
		AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
		String incorrectCaptchaMsg = captchaConfig.getConfig().get(Constants.INCORRECT_CAPTCHA_MSG);
		String captcha = formData.getFirst("user_captcha");
		String captchaSecret = formData.getFirst("captcha_secret");
		UserLoginFailureProvider user = context.getSession().loginFailures();
		
		if (!Validation.isBlank(captcha)) {

			success = validateRecaptcha(context, success, captcha, captchaSecret);
		}
		if (success) {
			super.action(context);
		} else {
			
			context.form().setAttribute("captchaError", true);
			
			Response challengeResponse = challenge(context, incorrectCaptchaMsg, "CAPTCHA_INPUT");
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
		
			return; 
		}

		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - end");
		}
	}

	protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String captchaSecret) {
		HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
		
		
		try {
			AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
			String validateCaptchaAPI = captchaConfig.getConfig().get(Constants.VALIDATE_CAPTCHA_API);
			HttpPost post = new HttpPost(validateCaptchaAPI);
			
			logger.info("captcha:: "+captcha);
			logger.info("captcha secret:: "+ captchaSecret);
			
			post.setHeader("Content-Type", "application/json");
			String jsonPayload = String.format("{\"data\": { \"captcha\":\"%s\", \"captcha_id\":\"%s\" }}",captcha, captchaSecret);
			
			
            
			logger.info(jsonPayload);
			post.setEntity(new StringEntity(jsonPayload, "UTF8")); 
			
			HttpResponse response = httpClient.execute(post);
			InputStream content = response.getEntity().getContent();
			
			try {
				Map json = JsonSerialization.readValue(content, Map.class);

				Object success_resp = json.get("status");
				if(success_resp!=null & success_resp.equals("success")) {
					success = Boolean.TRUE;
				}
		
			} finally {
				content.close();
			}
		} catch (Exception e) {
			ServicesLogger.LOGGER.recaptchaFailed(e);
		}
		return success;
	}

}
