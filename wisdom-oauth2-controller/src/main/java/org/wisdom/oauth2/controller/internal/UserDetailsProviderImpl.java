package org.wisdom.oauth2.controller.internal;

import org.apache.felix.ipojo.annotations.*;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.oauth2.controller.UserDetails;
import org.wisdom.oauth2.controller.UserDetailsProvider;

import java.util.Map;

/**
 * Created by cheleb on 30/01/15.
 */
@Component
@Provides
@Instantiate
public class UserDetailsProviderImpl implements UserDetailsProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserDetailsProviderImpl.class);

    private String userinfoURL;

    private String userinfoEmail;

    @Requires
    private ApplicationConfiguration configuration;

    @Validate
    public void validate(){
        this.userinfoURL = configuration.get("oauth2.userinfo.url");
        this.userinfoEmail = configuration.get("oauth2.userinfo.email");
    }

    @Override
    public UserDetails getUserDetails(String accessToken) {
        try {
            String email = getEmail(accessToken);
            return new UserDetails(email);
        } catch (OAuthSystemException | OAuthProblemException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * @param accessToken
     * @return
     * @throws org.apache.oltu.oauth2.common.exception.OAuthSystemException
     * @throws org.apache.oltu.oauth2.common.exception.OAuthProblemException
     */
    private String getEmail(String accessToken) throws OAuthSystemException, org.apache.oltu.oauth2.common.exception.OAuthProblemException {
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        try {
            OAuthBearerClientRequest authBearerClientRequest = new OAuthBearerClientRequest(userinfoURL);
            OAuthClientRequest loginRequest = authBearerClientRequest.setAccessToken(accessToken).buildHeaderMessage();

            OAuthResourceResponse resource = oAuthClient.resource(loginRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);

            Map<String, Object> parseJSON = JSONUtils.parseJSON(resource.getBody());
            if (parseJSON == null) {
                LOGGER.warn("Could not retrieve userinfo from [" + userinfoURL + "]");
                return null;
            }

            Object email = parseJSON.get(userinfoEmail);
            if (email == null) {
                LOGGER.warn("Could not retrieve email from key: " + userinfoEmail);
                if (LOGGER.isDebugEnabled()) {
                    for (Map.Entry<String, Object> e : parseJSON.entrySet()) {
                        LOGGER.debug(e.getKey() + " -> " + e.getValue());
                    }

                }
                return null;
            }
            return email.toString();
        } finally {
            oAuthClient.shutdown();
        }

    }
}
