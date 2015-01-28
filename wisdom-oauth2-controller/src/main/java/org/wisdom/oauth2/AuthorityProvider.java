package org.wisdom.oauth2;

import org.wisdom.api.http.Request;
import org.wisdom.api.http.Result;

import java.util.Set;

/**
 * Created by mackristof
 */
public interface AuthorityProvider {

    Set<String> getAuthority(String userId);

    Result handle(Request request);

}
