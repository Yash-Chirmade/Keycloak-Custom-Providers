package co.remiges.tech.emailservice;

import java.util.Objects;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.actiontoken.resetcred.ResetCredentialsActionToken;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialEmail;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.DefaultActionTokenKey;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.LoginProtocol.Error;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

import co.remiges.tech.emailservice.EmailService.EmailResponse;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;


public class CustomResetCredentialEmail extends ResetCredentialEmail {

    private static final Logger logger = Logger.getLogger(CustomResetCredentialEmail.class);
    private EmailService emailService = new EmailService();
    private static final String FORGOT_PASSWORD_EMAIL_SENT = "Password reset mail sent to your registered email id";
    


 @Override
 public void authenticate(AuthenticationFlowContext context) {
     logger.info("Custom Reset Credential Email");
     UserModel user = context.getUser();
     logger.info("User fetched successfully " );
     logger.info("User: " + user);
     if (user == null) {
         context.failure(AuthenticationFlowError.INVALID_USER, null);
         return;
     }
     AuthenticatorConfigModel config = context.getAuthenticatorConfig();
     AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
     String username = user.getUsername();
     String forgotPasswordEmailMessage = String.format("%s",FORGOT_PASSWORD_EMAIL_SENT);
     EmailResponse emailResponse;

    String actionTokenUserId = authenticationSession.getAuthNote(DefaultActionTokenKey.ACTION_TOKEN_USER_ID);
    logger.info("actionTokenUserId: " + actionTokenUserId);
    if (actionTokenUserId != null && Objects.equals(user.getId(), actionTokenUserId)) {
            logger.infof("Forget-password triggered when reauthenticating user after authentication via action token. Skipping " + PROVIDER_ID + " screen and using user '%s' ", user.getUsername());
            context.success();
            return;
    }
     int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan(ResetCredentialsActionToken.TOKEN_TYPE);
     int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
 
     String authSessionEncodedId = AuthenticationSessionCompoundId.fromAuthSession(authenticationSession).getEncodedId();
     ResetCredentialsActionToken token = new ResetCredentialsActionToken(
    user.getId(), 
    user.getEmail(), 
    absoluteExpirationInSecs, 
    authSessionEncodedId, 
    authenticationSession.getClient().getClientId());
 
     // Create a link to the reset password page     
     String link = UriBuilder
         .fromUri(context.getActionTokenUrl(token.serialize(context.getSession(), context.getRealm(), context.getUriInfo())))
         .build()
         .toString();
    
    logger.info("Link for reset password: " + link);
     String emailId = user.getFirstAttribute("email");
     logger.info("Email Id recieved:" + emailId);
     String subject = "Reset Credentials for BSE StArmf";
     String htmlMessage = buildHtmlContent(link,username);
     String apiKey = config.getConfig().get("netcoreApiKey");
     String apiUrl = config.getConfig().get("netcoreApiUrl");
     String proxyHost = config.getConfig().get("proxyHost");
     String proxyPort = config.getConfig().get("proxyPort");
     boolean skiptls = Boolean.parseBoolean(config.getConfig().get("skiptls"));
     boolean isProxyRequired = Boolean.parseBoolean(config.getConfig().get("isProxyRequired"));
     if ((emailId != null) &&  (!isProxyRequired) ){
         try {
             emailResponse = emailService.sendEmailWithoutProxy(emailId, subject, htmlMessage, apiKey, apiUrl);
             if (!emailResponse.isSuccess()) {
                context.failure(AuthenticationFlowError.INTERNAL_ERROR, null);
                System.out.println("Failed to send email: " + emailResponse.getErrorMessage());
            } else {
                context.forkWithSuccessMessage(new FormMessage(forgotPasswordEmailMessage)); 
                return;           
            }
             
         } catch (Exception e) {
             logger.error("Failed to send email", e);
             // Create a Response that indicates an error and pass it to context.failure
             Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                                        .entity("Failed to send email due to server error").build();
             context.failure(AuthenticationFlowError.ACCESS_DENIED, response);
         }
     } else if ((emailId != null) &&  (isProxyRequired)){
        if (proxyHost == null || proxyPort == null) {
            logger.error("Proxy host or port is null");
            // Create a Response that indicates an error and pass it to context.failure
            Response response = Response.status(Response.Status.BAD_REQUEST)
                                       .entity("Proxy host or port is null").build();
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
        }
        try {
           emailResponse = emailService.sendEmailWithProxy(emailId, subject, htmlMessage, apiKey, apiUrl,proxyHost,proxyPort,skiptls);
            if (!emailResponse.isSuccess()) {
                context.failure(AuthenticationFlowError.ACCESS_DENIED, null);
                System.out.println("Failed to send email: " + emailResponse.getErrorMessage());
            } else {
                context.forkWithSuccessMessage(new FormMessage(forgotPasswordEmailMessage)); 
                return;           
            }
        } catch (Exception e) {
            logger.error("Failed to send email" + e.getMessage(), e);
            // Create a Response that indicates an error and pass it to context.failure
            Response response = Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                                       .entity("Failed to send email due to server error").build();
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, response);
        }
        
     }else{
         // Log and handle the null or invalid email case
         logger.error("Email ID is null or invalid for user: " + user.getUsername());
         Response response = Response.status(Response.Status.BAD_REQUEST)
                                    .entity(
                                        "Invalid or missing email attribute").build();
         context.failure(AuthenticationFlowError.INVALID_USER, response);
     }
 }


 private String buildHtmlContent(String link, String username) {
    return "<html><body>" +
           "<p>Dear " + username + ",</p>" +
           "<p>Please click on the link below to reset your password:</p>" +
           "<a href='" + link + "' style='padding: 10px; background-color: #007BFF; color: white; text-decoration: none; border-radius: 5px;'>Reset Password</a>" +
           "<p>If you did not request a password reset, please ignore this email.</p>" +
           "</body></html>";
}
}
