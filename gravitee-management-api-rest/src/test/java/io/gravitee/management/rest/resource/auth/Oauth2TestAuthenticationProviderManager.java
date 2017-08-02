package io.gravitee.management.rest.resource.auth;

import com.google.common.base.Throwables;
import io.gravitee.management.security.authentication.AuthenticationProvider;
import io.gravitee.management.security.authentication.AuthenticationProviderManager;
import io.gravitee.management.security.authentication.impl.OAuth2AuthenticationProvider;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Created by Christophe on 02/08/2017.
 */
class Oauth2TestAuthenticationProviderManager implements AuthenticationProviderManager {

    private OAuth2AuthenticationProvider oAuth2AuthenticationProvider;

    Oauth2TestAuthenticationProviderManager() {}

    @Override
    public List<AuthenticationProvider> getIdentityProviders() {
        return Collections.singletonList(getOAuth2AuthenticationProvider());
    }

    @Override
    public Optional<AuthenticationProvider> findIdentityProviderByType(String type) {
        if("oauth2".equals(type)) {
            return Optional.of(getOAuth2AuthenticationProvider());
        } else {
            return Optional.empty();
        }
    }

    private OAuth2AuthenticationProvider getOAuth2AuthenticationProvider() {
        if(oAuth2AuthenticationProvider == null) {
            oAuth2AuthenticationProvider = createOAuth2AuthenticationProvider();

            oAuth2AuthenticationProvider.setConfiguration(createConfigMap());
        }
        return oAuth2AuthenticationProvider;
    }

    private OAuth2AuthenticationProvider createOAuth2AuthenticationProvider() {
        Constructor<OAuth2AuthenticationProvider> constructor = null;
        try {
            constructor = OAuth2AuthenticationProvider.class.getDeclaredConstructor(new Class[]{String.class,int.class});
        }
        catch (NoSuchMethodException e) {
            throw Throwables.propagate(e);
        }
        constructor.setAccessible(true);
        try {
            return constructor.newInstance(new Object[]{"oauth2",0});
        }
        catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw Throwables.propagate(e);
        }
    }

    private Map<String,Object> createConfigMap() {
        Map<String,Object> configuration = new HashMap<>();
        configuration.put("clientId","the_client_id");
        configuration.put("clientSecret","the_client_secret");
        return configuration;
    }

}
