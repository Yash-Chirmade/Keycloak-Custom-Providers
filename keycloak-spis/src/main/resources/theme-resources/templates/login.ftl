<#import "template.ftl" as layout>
<#import "components/provider.ftl" as provider>
<#import "components/button/primary.ftl" as buttonPrimary>
<#import "components/checkbox/primary.ftl" as checkboxPrimary>
<#import "components/input/primary.ftl" as inputPrimary>
<#import "components/label/username.ftl" as labelUsername>
<#import "components/link/primary.ftl" as linkPrimary>

<@layout.registrationLayout
  displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??
  displayMessage=!messagesPerField.existsError("username", "password")
  ;
  section
>
  <#if section="header">
    ${msg("loginAccountTitle")}
  <#elseif section="form">
    <#if realm.password>
      <form
        style="display: flex;flex-direction: column;justify-content: center;align-items: center;"
        action="${url.loginAction}"
        class="m-0 space-y-4"
        method="post"
        onsubmit="login.disabled = true; return true;"
      >
        <input
          name="credentialId"
          type="hidden"
          value="<#if auth.selectedCredential?has_content>${auth.selectedCredential}</#if>"
        >
        <div>
        <span class="fs-18 fw-700"><@labelUsername.kw /></span>
          <@inputPrimary.kw
            autocomplete=realm.loginWithEmailAllowed?string("email", "username")
            autofocus=true
            disabled=usernameEditDisabled??
            invalid=["username", "password"]
            name="username"
            type="text"
            value=(login.username)!''
          >
            ${msg("userId")}
          </@inputPrimary.kw>
        </div>
        <div>
        <span class="fs-18 fw-700">${msg("password")}</span>
          <@inputPrimary.kw
            invalid=["username", "password"]
            message=false
            name="password"
            type="password"
          >
            ${msg("password")}
          </@inputPrimary.kw>
        </div>
        <div class="flex items-center" style="display: flex; justify-content: between; align-items: center; gap: 3.5rem;">
          <#if realm.rememberMe && !usernameEditDisabled??>
            <@checkboxPrimary.kw checked=login.rememberMe?? name="rememberMe">
              <span class="fs-18 fw-600">${msg("rememberMe")}</span>
            </@checkboxPrimary.kw>
          </#if>
          <#if realm.resetPasswordAllowed>
            <@linkPrimary.kw href=url.loginResetCredentialsUrl>
              <span class="fs-18 fw-600">${msg("doForgotPassword")}</span>
            </@linkPrimary.kw>
          </#if>
        </div>
        <div class="pt-4" >
          <@buttonPrimary.kw name="login" type="submit">
            ${msg("doLogIn")}
          </@buttonPrimary.kw>
        </div>
		
		<div>
			<img id="captchaImage" alt="Captcha Image">
		</div>
				
		<script>
			window.onload = function() {
  
				// Replace with your actual API endpoint
				const apiUrl = 'http://localhost:8081/unified-portal/api/auth/captcha';
				var captcha_image="";
				// Make a GET request to the API
				fetch(apiUrl)
                .then(response => {
                    return response.json();
                })
                .then(data => {
                    // Handle the API response data
					captcha_image =  data.response.realCaptcha;
					document.getElementById('captchaImage').src = 'data:image/jpg;base64,'+ captcha_image;
                })
                .catch(error => {
                    console.error('Fetch Error:', error);
                    alert('Error calling API: ' + error.message);
                });
 
			};
		
		</script>
		
		 <div class="form-group">
						<label for="user_captcha" class="col-md-2 control-label">user_captcha</label>
							<div class="col-md-10">
								<input type="text" class="form-control" id="user_captcha" name="user_captcha" />
							</div>
					</div>
		
		
		
		
      </form>
    </#if>
    <#if realm.password && social.providers??>
      <@provider.kw />
    </#if>
  <#elseif section="info">
    <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
      <div class="text-center pt-4" style="display:flex; justify-content:center;">
        <span class="fs-18 fw-600">${msg("noAccount")}</span>
        <@linkPrimary.kw href="https://saralsanchar.gov.in/admin/olmRegistration_add.php">
          <span class="fs-18 fw-600">${msg("doRegister")}</span>
        </@linkPrimary.kw>
      </div>
    </#if>
  </#if>
</@layout.registrationLayout>
