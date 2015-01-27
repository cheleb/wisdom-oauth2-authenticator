package org.wisdom.oauth2;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Provides;
import org.wisdom.api.http.Result;
import org.wisdom.api.http.Status;
import org.wisdom.api.interception.Interceptor;
import org.wisdom.api.interception.RequestContext;

import java.util.Set;

/**
 * Created by cheleb on 27/01/15.
 */
@Component
@Provides(specifications = Interceptor.class)
@Instantiate
public class RoleInterceptor extends Interceptor<Role> {
    @Override
    public Result call(Role configuration, RequestContext context) throws Exception {
        Object rolesAsO = context.data().get("roles");
        if (rolesAsO == null)
            return new Result().status(Status.FORBIDDEN);
        Set<String> roles = (Set<String>) rolesAsO;
        if (roles.contains(configuration.value()))
            return context.proceed();
        return new Result().status(Status.FORBIDDEN);
    }

    @Override
    public Class<Role> annotation() {
        return Role.class;
    }
}
