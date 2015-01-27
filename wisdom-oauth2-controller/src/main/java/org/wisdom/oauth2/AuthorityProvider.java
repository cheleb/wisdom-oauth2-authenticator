package org.wisdom.oauth2;

import java.util.Set;

/**
 * Created by mackristof
 */
public interface AuthorityProvider {
    public Set<String> getAuthority(String userId);
}
