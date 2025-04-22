package co.remiges.tech.smsservice;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpResponse;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.TokenCategory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.ServerCookie;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.sessions.AuthenticationSessionModel;
import co.remiges.tech.Constants;
import co.remiges.tech.emailservice.EmailService;
import co.remiges.tech.emailservice.EmailService.EmailResponse;
import co.remiges.tech.smsservice.smsgateway.SmsServiceFactory;
import jakarta.ws.rs.core.*;
import java.net.URI;
import java.time.LocalDateTime;

/**
 * This SPI can be used to send SMS OTP for Login Authentication using Keycloak.
 * To enable SMS OTP as a step in Authentication Workflow, 1. Login to Keycloak
 * Admin Portal. 2. Click on the relevant Realm on top Left corner. 3. Click on
 * "Authentication" in "configure" section on left sidebar. 4. we'll create a
 * copy of existing "Browser" workflow for our use. a. Click on "Browser"
 * authentication flow b. on top right, there is a drop down named 'Action',
 * select duplicate from it. This will create a duplicate browser authentication
 * flow c. Name this new workflow to example 'browserWithSMSOtp' d. In
 * 'browserWithSMSOtp forms' section, add a sub-section by clicking on '+'
 * symbol besides the step and click on 'Add step' e. In the list search for
 * 'SMS Authentication'. f. Add an alias to this setting, and set the parameters
 * 'Code length' i.e. SMS OTP length 'Time-to-live' i.e. TTL for which OTP is
 * valid 'SenderId' i.e. What should be the SenderId in the SMS OTP 'Simulation
 * mode' i.e. if on, it'll not actually send the OTP instead just print OTP in
 * console g. Click on save h. Now set the flow to be used for browser. So click
 * on drop down 'Action' on top right and click on 'Bind Flow' and select
 * 'Browser flow' and click on 'Save'
 * 
 * @author bhavyag
 *
 */
public class SmsAuthenticator implements Authenticator {

	private static final String TPL_CODE = "login-sms.ftl";
	private static final Logger LOG = Logger.getLogger(SmsAuthenticator.class);
	private static final String CONST_REALM = "realm";
	private EmailService emailService;
	private static final String OTP_SENT = "otp sent successfully";

	public SmsAuthenticator() {
		this.emailService = new EmailService(); // Initialize the email service
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		UserModel user = context.getUser();
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		String mobileNumber = "";

		/**
		 * Fetch mobile no from User attribute of Keycloak
		 */
		mobileNumber = user.getFirstAttribute(Constants.ATTRIB_MOB_NUM);
		if (mobileNumber == null || mobileNumber.isBlank()) {
			String errorString = String.format(
					"'%s' attribute for the user <%s>is blank or not present. Please set it.", Constants.ATTRIB_MOB_NUM,
					user.getUsername());
			LOG.error(errorString);
		}

		try {
			AuthenticationSessionModel authSession = context.getAuthenticationSession();

			String rememberMe = formData.containsKey("rememberMe") ? formData.getFirst("rememberMe") : "off";
			String errorString = String.format("rememberMe:: '%s'", rememberMe);
			LOG.info(errorString);
			authSession.setAuthNote("rememberMe", rememberMe);
			if (rememberMe.equalsIgnoreCase("on")) {
				if (hasCookie(context)) {
					context.success();
					return;
				}
			}

			/*
			 * If OTP wasrememberMe = formData.containsKey("rememberMe") ?
			 * formData.getFirst("rememberMe") : "off"; already generated, and is valid,
			 * then there is no need to re-generate the OTP.
			 */
			if (authSession.getAuthNote("code") != null
					&& Long.parseLong(authSession.getAuthNote("ttl")) > System.currentTimeMillis()) {
				context.attempted();
				return;
			}
			/*
			 * length: Length of OTP to be generated. This is currently defined in the
			 * Authentication flow. Can be read from config as well.
			 */
			int length = Integer.parseInt(config.getConfig().get("length"));
			/*
			 * Generating OTP
			 */
			String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
			/*
			 * Set OTP in current device session
			 */
			authSession.setAuthNote("code", code);
			authSession.setAuthNote("resendOtpLimit", config.getConfig().get("resendOtpLimit"));
			authSession.setAuthNote("length", config.getConfig().get("length"));
			authSession.setAuthNote("invalidOtpCount", "0");
			authSession.setAuthNote("resendOtpCount", "0");
			/*
			 * Send OTP
			 */
			sendOTP(context, code);

		} catch (NumberFormatException e) {
			LOG.error(String.format("Unable to parse length<%s> or ttl<%s> for the Authentication Flow",
					config.getConfig().get("length"), config.getConfig().get("ttl")));
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("smsAuthSmsNotSent", e.getMessage())
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	/**
	 * Method to Send OTP via both SMS and EMail
	 * 
	 * @param context AuthenticationFlowContext
	 * @param code    OTP code
	 */
	private void sendOTP(AuthenticationFlowContext context, String code) {

		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		String otpSentMessage = String.format("%s", OTP_SENT);
		EmailResponse emailResponse = null;

		/*
		 * ttl: Time to Live of OTP to be generated
		 */
		int ttl = Integer.parseInt(config.getConfig().get("ttl"));

		try {
			/*
			 * SMS OTP Send
			 */
			String mobileNumber = "";
			/**
			 * Fetch mobile no from User attribute of Keycloak
			 */

			mobileNumber = user.getFirstAttribute(Constants.ATTRIB_MOB_NUM);
			System.out.println("mobileNumber:: " + mobileNumber);
			if (mobileNumber == null || mobileNumber.isBlank()) {
				String errorString = String.format(
						"'%s' attribute for the user <%s>is blank or not present. Please set it.",
						Constants.ATTRIB_MOB_NUM, user.getUsername());
				LOG.error(errorString);
			}

			if (mobileNumber != null) {
				// Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
				// Locale locale = session.getContext().resolveLocale(user);
				// String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
				// String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));
				String smsText = String.format(
						"%s is the OTP to access BSE StAR MF platform for user: %s%s%s. OTP valid for %s . Pls do not share it with anyone.",
						code,
						" " + user.getFirstName(), " " + user.getLastName(), " username: " + user.getUsername(),
						Math.floorDiv(ttl, 60) + " Minutes");

				SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
			}
			/*
			 * Email OTP Send
			 */
			// sendEmailWithCode(session, context.getRealm(), user, code);

			String emailId = user.getFirstAttribute("email");
			LOG.info("emailId:: " + emailId);
			// String emailId = "sea.yash29@gmail.com";
			String mailSendMsg = String.format(
					"%s is the OTP to access BSE StAR MF platform for user: %s%s%s. OTP valid for %s . Pls do not share it with anyone.",
					code,
					" " + user.getFirstName(), " " + user.getLastName(), " username: " + user.getUsername(),
					Math.floorDiv(ttl, 60) + " Minutes");
			String apiKey = config.getConfig().get("netcoreApiKey");
			String apiUrl = config.getConfig().get("netcoreApiUrl");
			String proxyHost = config.getConfig().get("proxyHost");
			String proxyPort = config.getConfig().get("proxyPort");
			boolean skiptls = Boolean.parseBoolean(config.getConfig().get("skiptls"));
			boolean isProxyRequired = Boolean.parseBoolean(config.getConfig().get("isProxyRequired"));
			String subject = "OTP for Login to BSE StArmf";
			if ((emailId != null) && (!isProxyRequired)) {
				try {
					emailResponse = emailService.sendEmailWithoutProxy(emailId, subject, mailSendMsg, apiKey, apiUrl);
					if (!emailResponse.isSuccess()) {
						context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError("emailSendFailed").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
						System.out.println("Failed to send email: " + emailResponse.getErrorMessage());
					}
					// else {
					// context.forkWithSuccessMessage(new FormMessage(otpSentMessage));
					// return;
					// }
				} catch (Exception e) {
					LOG.error("Failed to send email" + e.getMessage(), e);
					// Create a Response that indicates an error and pass it to context.failure
					Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
							.entity("Failed to send email due to server error").build();
					context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
				}
			} else if ((emailId != null) && (isProxyRequired)) {
				try {
					emailResponse = emailService.sendEmailWithProxy(emailId, subject, mailSendMsg, apiKey, apiUrl,
							proxyHost, proxyPort, skiptls);
					if (!emailResponse.isSuccess()) {
						context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().setError("emailSendFailed").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
						System.out.println("Failed to send email: " + emailResponse.getErrorMessage());
					}
					// else {
					// context.forkWithSuccessMessage(new FormMessage(otpSentMessage));
					// return;
					// }
				} catch (Exception e) {
					LOG.error("Failed to send email" + e.getMessage(), e);
					// Create a Response that indicates an error and pass it to context.failure
					Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
							.entity("Failed to send email due to server error").build();
					context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
				}

			} else {
				// Log and handle the null or invalid email case
				LOG.error("Email ID is null or invalid for user: " + user.getUsername());
				Response response = Response.status(Response.Status.BAD_REQUEST)
						.entity("Invalid or missing email attribute").build();
				context.failure(AuthenticationFlowError.INVALID_USER, response);
			}
			String otpSendMsg = "";

			if (emailResponse != null && emailResponse.isSuccess()) {
				otpSendMsg += "Email sent to " + obfuscateEmail(user.getFirstAttribute("email")) + ". ";
			}
			
			if (mobileNumber != null && !mobileNumber.isBlank()) {
				otpSendMsg += "OTP also sent to your registered mobile number.";
			} else {
				otpSendMsg += "No mobile number found.";
			}
			
			context.form().setAttribute("isOtpSendMsgSet", true);
			context.form().setAttribute("otpSendMsg", otpSendMsg);
			context.getAuthenticationSession().setAuthNote("ttl",
					Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
			
			context.challenge(context.form().setAttribute(CONST_REALM, context.getRealm()).createForm(TPL_CODE));
			

		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("smsAuthSmsNotSent", e.getMessage())
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	public String obfuscateEmail(String email) {
		if (email == null || !email.contains("@")) {
			// Invalid email format
			return email;
		}

		String[] parts = email.split("@");
		String localPart = parts[0];
		String domainPart = parts[1];

		// Obfuscate the local part
		String obfuscatedLocalPart = obfuscateLocalPart(localPart);
		String obfuscateDomainPart = obfuscateDomainPart(domainPart);

		// Return the obfuscated email
		return obfuscatedLocalPart + "@" + obfuscateDomainPart
				+ domainPart.substring(domainPart.indexOf("."), domainPart.length());
	}

	private String obfuscateLocalPart(String localPart) {
		int length = localPart.length();
		if (length <= 2) {
			// If the local part has 2 or fewer characters, don't obfuscate
			return localPart;
		}

		// Obfuscate all characters except the first and last two
		String prefix = localPart.substring(0, 2);
		String suffix = localPart.substring(length - 2);
		String obscuredPart = localPart.substring(2, length - 2).replaceAll(".", "*");

		return prefix + obscuredPart + suffix;
	}

	private String obfuscateDomainPart(String domainPart) {

		String obscuredPart = domainPart.substring(0, domainPart.indexOf(".")).replaceAll(".", "*");

		return obscuredPart;
	}

	@Override
	public void action(AuthenticationFlowContext context) {

		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		int validateOtpLimitConfig = 0;
		int invalidOtpCount = 0;
		String smsResendLimitExhausted = "Resend otp attempts exhausted. Try after "
				+ config.getConfig().get("retryAfterTime") + " minutes.";
		try {
			if (formData.containsKey("resend")) {

				boolean resendOtp = isResendOtpLimitExceeded(context);
				boolean tryAfter = false;

				if (resendOtp) {
					tryAfter = checkRetryAfter(context);
					if (!tryAfter) {
						context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
								context.form().setAttribute(CONST_REALM, context.getRealm())
										.setError(smsResendLimitExhausted).createForm(TPL_CODE));
						return;
					}
				}

				LOG.info("inside resend login otp");
				authSession.setAuthNote("invalidOtpCount", String.valueOf(0));

				int length = Integer.parseInt(authSession.getAuthNote("length"));
				String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
				sendOTP(context, code);
				authSession.setAuthNote("code", code);
				LOG.info(String.format("Resending OTP for user <%s>", context.getUser().getUsername()));
				context.challenge(context.form().setAttribute(CONST_REALM, context.getRealm()).createForm(TPL_CODE));
				return;
			}

			validateOtpLimitConfig = Integer.parseInt(config.getConfig().get("validateOtpLimit"));
			invalidOtpCount = Integer.parseInt(context.getAuthenticationSession().getAuthNote("invalidOtpCount"));
			if (invalidOtpCount >= validateOtpLimitConfig) {
				LOG.info("Validate otp attempts exhausted");
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
						context.form().setAttribute(CONST_REALM, context.getRealm()).setError("smsOtpLimitExhausted")
								.createForm(TPL_CODE));
				return;
			}

			context.form().setAttribute("isOtpSendMsgSet", false);
			context.form().setAttribute("otpSendMsg", "");

			String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

			String code = authSession.getAuthNote("code");
			String ttl = authSession.getAuthNote("ttl");

			if (code == null || ttl == null) {
				context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
						context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
				return;
			}

			boolean isValid = enteredCode.equals(code);
			if (isValid) {
				if (Long.parseLong(ttl) < System.currentTimeMillis()) {
					/*
					 * OTP expired
					 */
					context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
							context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
				} else {
					/*
					 * OTP is valid
					 */
					// TODO change logging to debug
					String rememberMe = context.getAuthenticationSession().getAuthNote("rememberMe");
					LOG.info("OTP validation success for " + context.getUser().getEmail());
					context.success();
					if (rememberMe.equalsIgnoreCase("on")) {
						setCookie(context);
					}
					removeSessionOTP(context);
				}
			} else {
				// OTP is invalid

				int count = Integer.parseInt(context.getAuthenticationSession().getAuthNote("invalidOtpCount"));
				authSession.setAuthNote("invalidOtpCount", String.valueOf(count + 1));
				LOG.debug(String.format("set otp limit: <%s>", String.valueOf(count + 1)));

				LOG.error(String.format(
						"OTP validation failed for user ,<%s>. Entered OTP <%s> does not match with required OTP <%s>",
						context.getUser().getUsername(), enteredCode, code));
				AuthenticationExecutionModel execution = context.getExecution();
				if (execution.isRequired()) {
					context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
							context.form().setAttribute(CONST_REALM, context.getRealm()).setError("smsAuthCodeInvalid")
									.createForm(TPL_CODE));
				} else if (execution.isConditional() || execution.isAlternative()) {
					context.attempted();
				}
			}
		} catch (Exception e) {
			LOG.error(e.getMessage());
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, context.form()
					.setError("sessionExist", e.getMessage()).createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	private boolean checkRetryAfter(AuthenticationFlowContext context) {

		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		LocalDateTime resendOtpBloackTime = LocalDateTime.parse(authSession.getAuthNote("resendOtpBloackTime"));
		long retryTimeConfig = Integer.parseInt(config.getConfig().get("retryAfterTime"));

		LocalDateTime retryAfter = resendOtpBloackTime.plusMinutes(retryTimeConfig);
		LocalDateTime currentTime = LocalDateTime.now();

		LOG.info(String.format("Try resend otp after <%s>", String.valueOf(retryAfter)));

		if (currentTime.isAfter(retryAfter)) {
			authSession.setAuthNote("resendOtpCount", String.valueOf(0));
			return true;
		} else {
			return false;
		}
	}

	private boolean isResendOtpLimitExceeded(AuthenticationFlowContext context) {

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();

		int count = Integer.parseInt(context.getAuthenticationSession().getAuthNote("resendOtpCount"));
		authSession.setAuthNote("resendOtpCount", String.valueOf(count + 1));

		int resendOtpLimit = Integer.parseInt(config.getConfig().get("resendOtpLimit")) + 1;
		int resendOtpCount = Integer.parseInt(context.getAuthenticationSession().getAuthNote("resendOtpCount"));

		if (resendOtpCount >= resendOtpLimit) {
			LocalDateTime currTime = LocalDateTime.now();
			if (authSession.getAuthNote("resendOtpBloackTime") == null)
				authSession.setAuthNote("resendOtpBloackTime", String.valueOf(currTime));
			return true;
		} else {
			return false;
		}
	}

	private void removeSessionOTP(AuthenticationFlowContext context) {
		context.getAuthenticationSession().removeAuthNote("code");
		context.getAuthenticationSession().removeAuthNote("ttl");
	}

	/**
	 * Checks if cookie is present and is for the current user
	 * 
	 * @param context AuthenticationFlowContext
	 * @return boolean. True if Cookie is Present else False
	 */
	private boolean hasCookie(AuthenticationFlowContext context) {
		Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(Constants.COOKIE_2FA_ANSWERED);
		if (cookie != null) {
			String encryptedToken = getEncryptedCookieString(context);
			String encryptedCookieValue = cookie.getValue();
			if (encryptedCookieValue != null && encryptedCookieValue.equals(encryptedToken)) {
				LOG.info(Constants.COOKIE_2FA_ANSWERED + " cookie is set and valid.");
				return true;
			}
		}
		return false;
	}

	/**
	 * Sets an Encrypted Cookie for the user.
	 * 
	 * @param context AuthenticationFlowContext
	 */
	private void setCookie(AuthenticationFlowContext context) {

		String rememberMe = context.getAuthenticationSession().getAuthNote("rememberMe");

		if (!rememberMe.equalsIgnoreCase("on")) {
			return;
		}
		int maxCookieAge = 0;
		if (context.getAuthenticatorConfig() != null) {
			maxCookieAge = 60 * 60 * 24
					* Integer.valueOf(context.getAuthenticatorConfig().getConfig().get("cookieMaxAge"));
		}
		URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();
		addCookie(Constants.COOKIE_2FA_ANSWERED, getEncryptedCookieString(context), uri.getRawPath(), null, null,
				maxCookieAge, false, true);
	}

	/**
	 * Returns an Encrypted String for the User logged in
	 * 
	 * @param context
	 * @return String
	 */
	private String getEncryptedCookieString(AuthenticationFlowContext context) {
		return encryptToken(context, getUserAgentId(context));
	}

	/**
	 * Encrypts String passed
	 * 
	 * @param context AuthenticationFlowContext
	 * @param value   String to be encrypted
	 * @return String. Encrypted String
	 */
	private String encryptToken(AuthenticationFlowContext context, String value) {
		String algorithm = context.getSession().tokens().signatureAlgorithm(TokenCategory.INTERNAL);
		SignatureSignerContext signer = context.getSession().getProvider(SignatureProvider.class, algorithm).signer();
		return new JWSBuilder().jsonContent(value).sign(signer);
	}

	/**
	 * Fetches user agent from HTTP headers and appends it to username.
	 * 
	 * @param context AuthenticationFlowContext
	 * @return String
	 */
	private String getUserAgentId(AuthenticationFlowContext context) {
		MultivaluedMap<String, String> headers = context.getHttpRequest().getHttpHeaders().getRequestHeaders();
		String username = context.getUser().getUsername();
		String userAgent = headers.getFirst("User-Agent");
		String ip = context.getConnection().getRemoteAddr();
		return username + "_" + userAgent + "_" + ip;
	}

	/**
	 * Creates and adds a cookie to HTTP headers
	 * 
	 * @param name     Name of Cookie
	 * @param value    Value of the Cookie
	 * @param path
	 * @param domain
	 * @param comment
	 * @param maxAge   Validity of cookie
	 * @param secure
	 * @param httpOnly
	 */
	private static void addCookie(String name, String value, String path, String domain, String comment, int maxAge,
			boolean secure, boolean httpOnly) {
		HttpResponse response = ResteasyProviderFactory.getInstance().getContextData(HttpResponse.class);
		StringBuilder cookieBuf = new StringBuilder();
		ServerCookie.appendCookieValue(cookieBuf, 1, name, value, path, domain, comment, maxAge, secure, httpOnly,
				null);
		String cookie = cookieBuf.toString();
		response.getOutputHeaders().add(HttpHeaders.SET_COOKIE, cookie);
	}

	/**
	 * Method sends Email with OTP
	 * 
	 * @param session KeycloakSession
	 * @param realm   Realm of the user
	 * @param user    User
	 * @param code    OTP code to be sent
	 */
	private void sendEmailWithCode(KeycloakSession session, RealmModel realm, UserModel user, String code) {
		if (user.getEmail() == null) {
			LOG.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(),
					user.getUsername());
			throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
		}

		Map<String, Object> mailBodyAttributes = new HashMap<>();
		mailBodyAttributes.put("username", user.getUsername());
		mailBodyAttributes.put("code", code);

		String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
		List<Object> subjectParams = List.of(realmName);
		try {
			EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
			emailProvider.setRealm(realm);
			emailProvider.setUser(user);
			emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
		} catch (EmailException eex) {
			LOG.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
		}
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// return user.getFirstAttribute("mobile_number") != null;
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
	}

	@Override
	public void close() {
	}

}
