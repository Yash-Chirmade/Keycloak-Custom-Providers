package co.remiges.tech.usersession;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

/**
 * This SPI can be used to control number of user sessions.
 * We have set number of user sessions allowed is 1 and if user try to
 * login 2nd session then user will get popup confirmation box to ask whether user wants to 
 * override previous session or else cancel current login flow.
 * 
 */
public class UserSessionAuthenticator implements Authenticator {

	private static final Logger LOG = Logger.getLogger(UserSessionAuthenticator.class);
	private static final String CONST_REALM = "realm";
	private static final String SESSION_FORM = "sessionPopup.ftl";
	private static final String SESSION_ERROR_FORM = "sessionError.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();

		try {
			KeycloakSession session = context.getSession();

			RealmModel realmModel = session.getContext().getRealm();
			UserModel userModel = session.users().getUserById(realmModel, context.getUser().getId());

			long count = session.sessions().getUserSessionsStream(realmModel, userModel).count();
			long allowedSessionCount = 1;
			
			LOG.info(String.format("Total number of sessions <%s>", count));
			
			/**
			 * Check no of user session. If the count is more then or equal to 1, then display
			 * popup confirmation box.
			 * Note: Number of session counts starts from 0.
			 */
			if (count >= allowedSessionCount) {

				context.challenge(
						context.form().setAttribute(CONST_REALM, context.getRealm()).createForm(SESSION_FORM));
				return;
			}
			context.success();
			
		} catch (Exception e) {
			LOG.error(e.getMessage());
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
					context.form().setError("sessionExist", e.getMessage())
							.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		
		KeycloakSession session = context.getSession();
		RealmModel realmModel = session.getContext().getRealm();
		UserModel userModel = session.users().getUserById(realmModel, context.getUser().getId());
		
		try {
		boolean overrideSession = Boolean.parseBoolean(formData.getFirst("override_session"));
		LOG.info(String.format("user selected: %s", overrideSession));
		
		/**
		 * Check user selection. If user select "ok" then we get "true" and if user select "cancel"
		 * then we get "false"
		 */
		if (overrideSession) {
			
			/**
			 * Get all sessions from keycloak. Then loop through all sessions and check current session id
			 * is equal to session id from keycloak. If session id doen't match then remove that session
			 * from keycloak to override the current session.
			 */
			session.sessions().getUserSessionsStream(realmModel, userModel).forEach(userSession -> {
				if (!userSession.getId().equals(context.getAuthenticationSession().getParentSession().getId())) {
					session.sessions().removeUserSession(realmModel, userSession);
				}
			});

			context.success();
		} else {
			AuthenticationExecutionModel execution = context.getExecution();
			if (execution.isRequired()) {
				context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
						context.form().setAttribute(CONST_REALM, context.getRealm()).setError("sessionExist")
								.createForm(SESSION_ERROR_FORM));
				context.resetFlow();
			} else if (execution.isConditional() || execution.isAlternative()) {
				context.attempted();
			}	
		}
	} catch (Exception e) {
		LOG.error(e.getMessage());
		context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("sessionExist", e.getMessage())
						.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
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
