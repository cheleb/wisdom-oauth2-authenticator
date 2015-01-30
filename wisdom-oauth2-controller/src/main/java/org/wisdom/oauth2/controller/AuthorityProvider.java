package org.wisdom.oauth2.controller;

import org.wisdom.api.http.Request;
import org.wisdom.api.http.Result;
import org.wisdom.api.interception.RequestContext;

import java.util.Set;

/**
 * Created by mackristof
 */
public interface AuthorityProvider {

    Set<String> getAuthority(String userId);

    Result handle(RequestContext request, Set<String> roles);

}
