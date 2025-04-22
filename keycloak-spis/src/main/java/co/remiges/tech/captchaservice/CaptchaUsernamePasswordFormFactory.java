package co.remiges.tech.captchaservice;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
//import org.keycloak.authentication.authenticators.console.ConsoleUsernamePasswordAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import co.remiges.tech.Constants;

public class CaptchaUsernamePasswordFormFactory  implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "captcha-u-p-form";
    public static final CaptchaUsernamePasswordForm SINGLETON = new CaptchaUsernamePasswordForm();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    public Authenticator createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return SINGLETON;
        if (!OAuth2Constants.DISPLAY.equalsIgnoreCase(displayType)) return null;
        return SINGLETON;//ConsoleUsernamePasswordAuthenticator.SINGLETON;
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


    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return PasswordCredentialModel.TYPE;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Captcha Username Password Form";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password from login form with captcha";
    }

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(Constants.VALIDATE_CAPTCHA_API);
        property.setLabel("Validate captcha api");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Validate captcha api");
        CONFIG_PROPERTIES.add(property);
        
  
        property = new ProviderConfigProperty();
        property.setName(Constants.INCORRECT_CAPTCHA_MSG);
        property.setLabel("Incorrect captcha msg");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Incorrect captcha msg");
        CONFIG_PROPERTIES.add(property);
     
    }

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
