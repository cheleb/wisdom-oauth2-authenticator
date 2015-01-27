package org.wisdom.oauth2;

import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.validator.CodeValidator;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.wisdom.api.http.Request;

import java.util.List;
import java.util.Map;

/**
 * Created by cheleb on 19/01/15.
 */
public class WisdomOAuthClientResponse extends OAuthClientResponse {


    private final Request request;


    public WisdomOAuthClientResponse(Request request, CodeValidator codeValidator) {
        this.request = request;
        super.validator = codeValidator;

        Map<String, List<String>> params = request.parameters();
        for (Map.Entry<String, List<String>> entry : params.entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            if (!values.isEmpty()) {
                parameters.put(key, values.get(0));
            }
        }
    }



    public static WisdomOAuthClientResponse oauthCodeAuthzResponse(Request request)
            throws OAuthProblemException {
        WisdomOAuthClientResponse response = new WisdomOAuthClientResponse(request, new CodeValidator());
        response.validate();
        return response;
    }

    public String getAccessToken() {
        return getParam(OAuth.OAUTH_ACCESS_TOKEN);
    }

    public Long getExpiresIn() {
        String value = getParam(OAuth.OAUTH_EXPIRES_IN);
        return value == null? null: Long.valueOf(value);
    }

    public String getScope() {
        return getParam(OAuth.OAUTH_SCOPE);
    }

    public String getCode() {
        return getParam(OAuth.OAUTH_CODE);
    }

    public String getState() {
        return getParam(OAuth.OAUTH_STATE);
    }


    protected void setBody(String body) {
        this.body = body;
    }

    protected void setContentType(String contentType) {
        this.contentType = contentType;
    }

    protected void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }
}
