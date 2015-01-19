package org.wisdom.auth2;

import org.apache.felix.ipojo.annotations.Requires;
import org.apache.felix.ipojo.annotations.Validate;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.DefaultController;
import org.wisdom.api.annotations.Controller;
import org.wisdom.api.annotations.Path;
import org.wisdom.api.annotations.QueryParameter;
import org.wisdom.api.annotations.Route;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.http.HttpMethod;
import org.wisdom.api.http.Result;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * Created by cheleb on 19/01/15.
 */
@Controller
@Path("/oauth2")
public class CallbackController extends DefaultController {

    private static final Logger LOGGER = LoggerFactory.getLogger(CallbackController.class);

    private String clientId;
    private String clientSecret ;

    private String loginCallback;


    @Requires
    private ApplicationConfiguration configuration;
    private String userinfo;
    private String tokenLocation;
    private String redirectOnLogin;

    @Validate
    public void validate() {
        this.loginCallback = configuration.get("oauth2.callback");
        this.clientId = configuration.get("oauth2.clientId");
        this.clientSecret = configuration.get("oauth2.clientSecret");
        this.userinfo = configuration.get("oauth2.userinfo");
        this.tokenLocation = configuration.get("oauth2.tokenLocation");
        this.redirectOnLogin = configuration.get("oauth2.redirectOnLogin");
        init();
    }

    @Route(uri = "/cb", method = HttpMethod.GET)
    public Result logincb(@QueryParameter("code") String code) {


        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        try {
            WisdomOAuthClientResponse oar = WisdomOAuthClientResponse.oauthCodeAuthzResponse(request());
            String accessToken = getAccessToken(oar, oAuthClient);

            OAuthBearerClientRequest authBearerClientRequest = new OAuthBearerClientRequest(userinfo);
            OAuthClientRequest loginRequest = authBearerClientRequest.setAccessToken(accessToken).buildHeaderMessage();

            OAuthResourceResponse resource = oAuthClient.resource(loginRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);

            Map<String, Object> parseJSON = JSONUtils.parseJSON(resource.getBody());

            session("email", (String) parseJSON.get("email"));

            return redirect(redirectOnLogin + "?"+OAuth.OAUTH_ACCESS_TOKEN+"="+accessToken).with(OAuth.OAUTH_ACCESS_TOKEN, accessToken);

        } catch (OAuthProblemException | OAuthSystemException e) {
            LOGGER.warn(e.getMessage(), e);
            return internalServerError(e);
        } finally {
            oAuthClient.shutdown();
        }

    }


    private String getAccessToken(WisdomOAuthClientResponse oar, OAuthClient oAuthClient) throws OAuthSystemException, OAuthProblemException {
        String code = oar.getCode();
        OAuthClientRequest oAuthClientRequest = OAuthClientRequest.tokenLocation(tokenLocation)
                .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientId).setClientSecret(clientSecret).setRedirectURI(loginCallback)
                .setCode(code).buildQueryMessage();

        OAuthJSONAccessTokenResponse oAuthResponse = oAuthClient.accessToken(oAuthClientRequest, OAuthJSONAccessTokenResponse.class);
        return oAuthResponse.getAccessToken();
    }


    public static void init() {
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }
        }};

        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (GeneralSecurityException e) {
            System.out.println(e.getStackTrace());
        }
        return;
    }

}
