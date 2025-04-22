package co.remiges.tech.emailservice;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.*;

public class CustomResetCredentialEmailFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "reset-credential-email-custom";
    private static final CustomResetCredentialEmail SINGLETON = new CustomResetCredentialEmail();

    @Override
    public String getDisplayType() {
        return "Send Custom Reset Email";
    }

    @Override
    public String getReferenceCategory() {
        return null;
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
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Send email to user from custom service and wait for response.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
            new ProviderConfigProperty("netcoreApiKey", "Netcore Api Key", "Api Key for sending sms via Netcore", ProviderConfigProperty.PASSWORD, ""),
            new ProviderConfigProperty("netcoreApiUrl", "Netcore Api Url", "Api Url for sending sms via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("isProxyRequired", "Is Proxy Required?", "Is Proxy Required for sending sms or email via Netcore", ProviderConfigProperty.BOOLEAN_TYPE, "false"),
            new ProviderConfigProperty("proxyHost", "Proxy Host", "Proxy Host for sending sms or email via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("proxyPort", "Proxy Port", "Proxy Port for sending sms or email via Netcore", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("skiptls", "Skip TLS Verification", "Skip TLS verificaiton of server for sending sms or email via Netcore", ProviderConfigProperty.BOOLEAN_TYPE, true )

        );
    }


    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}