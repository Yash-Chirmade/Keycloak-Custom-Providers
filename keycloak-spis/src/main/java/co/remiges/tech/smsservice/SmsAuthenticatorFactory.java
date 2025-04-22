package co.remiges.tech.smsservice;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import co.remiges.tech.Constants;

/**
 * Factory class for SMS OTP send SPI
 * @author bhavyag
 */
public class SmsAuthenticatorFactory implements AuthenticatorFactory{

	private static final String PROVIDER_ID = "sms-authenticator";

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "SMS Authentication";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS to the users mobile phone.";
	}

	@Override
	public String getReferenceCategory() {
		return "otp";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty("feedid", "Feed Id", "Feed Id is used to send SMS.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("ttl", "Time to live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),//added 07/10
			new ProviderConfigProperty("smsApiUrl", "SMS Api Url", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty("username","Username","Username for sending email via Netcore",ProviderConfigProperty.STRING_TYPE,""),
			new ProviderConfigProperty("password","Password","Password for sending email via Netcore",ProviderConfigProperty.PASSWORD,""),
			new ProviderConfigProperty(Constants.ATTRIB_2FA_COOKIE, "Set Cookie For 2FA", "Set Cookie for 2FA which will disable 2FA for fixed days.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("cookieMaxAge", "Cookie Max Age in no of Days", "The number of days for which Cookie is valid for 2FA", ProviderConfigProperty.STRING_TYPE, "7"),
			new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty("validateOtpLimit", "Validate Otp Limit", "set number of attempt user can enter wrong otp", ProviderConfigProperty.STRING_TYPE, 3),
			new ProviderConfigProperty("resendOtpLimit", "Resend Otp Limit", "set number of attempt user can generate otp", ProviderConfigProperty.STRING_TYPE, 3),
			new ProviderConfigProperty("netcoreApiKey", "Netcore Api Key", "Api Key for sending email via Netcore", ProviderConfigProperty.PASSWORD, ""),
			new ProviderConfigProperty("netcoreApiUrl", "Netcore Api Url", "Api Url for sending email via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("retryAfterTime", "Retry After Time", "set retry afterTime in minuts", ProviderConfigProperty.STRING_TYPE, 30),
			new ProviderConfigProperty("isProxyRequired", "Is Proxy Required?", "Is Proxy Required for sending sms or email via Netcore", ProviderConfigProperty.BOOLEAN_TYPE, "false"),
            new ProviderConfigProperty("proxyHost", "Proxy Host", "Proxy Host for sending sms or email via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("proxyPort", "Proxy Port", "Proxy Port for sending sms or email via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("skiptls", "Skip TLS Verification", "Skip TLS verificaiton of server for sending sms or email via Netcore", ProviderConfigProperty.BOOLEAN_TYPE, true )
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return new SmsAuthenticator();
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}


}
