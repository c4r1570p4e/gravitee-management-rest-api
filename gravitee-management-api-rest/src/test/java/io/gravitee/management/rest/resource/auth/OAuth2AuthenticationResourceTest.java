/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.management.rest.resource.auth;

import com.auth0.jwt.JWTVerifier;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.management.model.NewExternalUserEntity;
import io.gravitee.management.model.UpdateUserEntity;
import io.gravitee.management.model.UserEntity;
import io.gravitee.management.rest.resource.AbstractResourceTest;
import io.gravitee.management.service.exceptions.UserNotFoundException;
import org.apache.commons.io.IOUtils;
import org.hamcrest.core.StringStartsWith;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static javax.ws.rs.client.Entity.json;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.refEq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


/**
 * Created by Christophe on 26/07/2017.
 */
public class OAuth2AuthenticationResourceTest extends AbstractResourceTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    public OAuth2AuthenticationResourceTest() {
        super(new Oauth2TestAuthenticationProviderManager());
    }

    protected String contextPath() {
        return "auth/oauth2";
    }

    @Before
    public void init() {
        cleanEnvironment();
        reset(userService);
    }

    private void cleanEnvironment() {
        getConfiguration().remove("tokenEndpoint");
        getConfiguration().remove("accessTokenProperty");
        getConfiguration().remove("userInfoEndpoint");
        getConfiguration().remove("authorizationHeader");
        getConfiguration().remove("mapping.email");
        getConfiguration().remove("mapping.id");
        getConfiguration().remove("mapping.lastname");
        getConfiguration().remove("mapping.firstname");
        getConfiguration().remove("mapping.picture");
    }

    private Map<String,Object> getConfiguration() {
        return this.authenticationProviderManager.getIdentityProviders().get(0).configuration();
    }

    @Test
    public void shouldConnectExistingUser() throws Exception {

        // -- MOCK
        //mock environment
        mockDefaultEnvironment();

        //mock oauth2 exchange authorisation code for access token
        mockExchangeAuthorizationCodeForAccessToken();

        //mock oauth2 user info call
        mockUserInfo(okJson(IOUtils.toString(read("/oauth2/json/user_info_response_body.json"), Charset.defaultCharset())));

        //mock DB find user by name
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername("janedoe@example.com");
        userEntity.setSource(AuthenticationSource.OAUTH2.getName());
        userEntity.setSourceId("248289761001");
        userEntity.setLastname("Doe");
        userEntity.setFirstname("Jane");
        userEntity.setEmail("janedoe@example.com");
        userEntity.setPicture("http://example.com/janedoe/me.jpg");

        when(userService.findByName("janedoe@example.com",false)).thenReturn(userEntity);

        //mock DB update user picture
        UpdateUserEntity user = new UpdateUserEntity();
        user.setUsername("janedoe@example.com");
        user.setPicture("http://example.com/janedoe/me.jpg");

        when(userService.update(refEq(user))).thenReturn(userEntity);

        //mock DB user connect
        when(userService.connect("janedoe@example.com")).thenReturn(userEntity);


        // -- CALL

        AbstractAuthenticationResource.Payload payload = createPayload("the_client_id","http://localhost/callback","CoDe","StAtE");;

        Response response = target().request().post(json(payload));

        // -- VERIFY
        verify(userService, times(1)).findByName("janedoe@example.com",false);
        verify(userService, times(0)).create(any());
        verify(userService, times(1)).update(refEq(user));
        verify(userService, times(1)).connect("janedoe@example.com");

        assertEquals(HttpStatusCode.OK_200, response.getStatus());

        // verify response body
        UserEntity responseUser = response.readEntity(UserEntity.class);

        assertEquals(responseUser.getEmail(),"janedoe@example.com");
        assertEquals(responseUser.getFirstname(),"Jane");
        assertEquals(responseUser.getLastname(),"Doe");
        assertEquals(responseUser.getUsername(),"janedoe@example.com");
        assertEquals(responseUser.getPicture(),"http://example.com/janedoe/me.jpg");
        assertEquals(responseUser.getSource(),"oauth2");


        // verify jwt token
        String cookieContent = response.getCookies().get(HttpHeaders.AUTHORIZATION).getValue();
        assertThat(cookieContent, StringStartsWith.startsWith("Bearer "));
        String jwt = cookieContent.substring(7);

        JWTVerifier jwtVerifier = new JWTVerifier("myJWT4Gr4v1t33_S3cr3t");

        Map<String, Object> mapJwt = jwtVerifier.verify(jwt);

        assertEquals(mapJwt.get("sub"),"janedoe@example.com");

        assertEquals(mapJwt.get("firstname"),"Jane");
        assertEquals(mapJwt.get("iss"),"gravitee-management-auth");
        assertEquals(mapJwt.get("sub"),"janedoe@example.com");
        assertEquals(mapJwt.get("email"),"janedoe@example.com");
        assertEquals(mapJwt.get("lastname"),"Doe");
    }

    private AbstractAuthenticationResource.Payload createPayload(String clientId, String redirectUri, String code, String state) {

        AbstractAuthenticationResource.Payload payload = new AbstractAuthenticationResource.Payload();
        payload.clientId = clientId;
        payload.redirectUri = redirectUri;
        payload.code = code;
        payload.state = state;

        return payload;
    }

    @Test
    public void shouldConnectNewUser() throws Exception {

        // -- MOCK
        //mock environment
        mockDefaultEnvironment();

        //mock oauth2 exchange authorisation code for access token
        mockExchangeAuthorizationCodeForAccessToken();

        //mock oauth2 user info call
        mockUserInfo(okJson(IOUtils.toString(read("/oauth2/json/user_info_response_body.json"), Charset.defaultCharset())));

        //mock DB find user by name
        when(userService.findByName("janedoe@example.com",false)).thenThrow(new UserNotFoundException("janedoe@example.com"));

        //mock create user

        NewExternalUserEntity newExternalUserEntity = new NewExternalUserEntity();
        newExternalUserEntity.setUsername("janedoe@example.com");
        newExternalUserEntity.setSource(AuthenticationSource.OAUTH2.getName());
        newExternalUserEntity.setSourceId("248289761001");
        newExternalUserEntity.setLastname("Doe");
        newExternalUserEntity.setFirstname("Jane");
        newExternalUserEntity.setEmail("janedoe@example.com");

        UserEntity createdUser = new UserEntity();
        createdUser.setUsername("janedoe@example.com");
        createdUser.setSource(AuthenticationSource.OAUTH2.getName());
        createdUser.setSourceId("248289761001");
        createdUser.setLastname("Doe");
        createdUser.setFirstname("Jane");
        createdUser.setEmail("janedoe@example.com");

        when(userService.create(refEq(newExternalUserEntity), eq(true))).thenReturn(createdUser);

        //mock DB update user picture
        UpdateUserEntity user = new UpdateUserEntity();
        user.setUsername("janedoe@example.com");
        user.setPicture("http://example.com/janedoe/me.jpg");

        createdUser.setPicture("http://example.com/janedoe/me.jpg");

        when(userService.update(refEq(user))).thenReturn(createdUser);


        //mock DB user connect
        when(userService.connect("janedoe@example.com")).thenReturn(createdUser);


        // -- CALL

        AbstractAuthenticationResource.Payload payload = createPayload("the_client_id","http://localhost/callback","CoDe","StAtE");;

        Response response = target().request().post(json(payload));

        // -- VERIFY
        verify(userService, times(1)).findByName("janedoe@example.com",false);
        verify(userService, times(1)).create(refEq(newExternalUserEntity),eq(true));

        verify(userService, times(1)).update(refEq(user));
        verify(userService, times(1)).connect("janedoe@example.com");

        assertEquals(HttpStatusCode.OK_200, response.getStatus());

        // verify response body
        UserEntity responseUser = response.readEntity(UserEntity.class);

        assertEquals(responseUser.getEmail(),"janedoe@example.com");
        assertEquals(responseUser.getFirstname(),"Jane");
        assertEquals(responseUser.getLastname(),"Doe");
        assertEquals(responseUser.getUsername(),"janedoe@example.com");
        assertEquals(responseUser.getPicture(),"http://example.com/janedoe/me.jpg");
        assertEquals(responseUser.getSource(),"oauth2");


        // verify jwt token
        String cookieContent = response.getCookies().get(HttpHeaders.AUTHORIZATION).getValue();
        assertThat(cookieContent, StringStartsWith.startsWith("Bearer "));
        String jwt = cookieContent.substring(7);

        JWTVerifier jwtVerifier = new JWTVerifier("myJWT4Gr4v1t33_S3cr3t");

        Map<String, Object> mapJwt = jwtVerifier.verify(jwt);

        assertEquals(mapJwt.get("sub"),"janedoe@example.com");

        assertEquals(mapJwt.get("firstname"),"Jane");
        assertEquals(mapJwt.get("iss"),"gravitee-management-auth");
        assertEquals(mapJwt.get("sub"),"janedoe@example.com");
        assertEquals(mapJwt.get("email"),"janedoe@example.com");
        assertEquals(mapJwt.get("lastname"),"Doe");

    }


    @Test
    public void shouldNotConnectUserOn401UserInfo() throws Exception {

        // -- MOCK
        //mock environment
        mockDefaultEnvironment();

        //mock oauth2 exchange authorisation code for access token
        mockExchangeAuthorizationCodeForAccessToken();

        //mock oauth2 user info call
        mockUserInfo(WireMock.unauthorized().withBody(IOUtils.toString(read("/oauth2/json/user_info_401_response_body.json"), Charset.defaultCharset())));

        // -- CALL

        AbstractAuthenticationResource.Payload payload = createPayload("the_client_id","http://localhost/callback","CoDe","StAtE");;

        Response response = target().request().post(json(payload));

        // -- VERIFY
        verify(userService, times(0)).findByName(anyString(), anyBoolean());
        verify(userService, times(0)).create(any());
        verify(userService, times(0)).update(any());
        verify(userService, times(0)).connect(anyString());

        assertEquals(HttpStatusCode.UNAUTHORIZED_401, response.getStatus());

        // verify jwt token not present

        assertFalse(response.getCookies().containsKey(HttpHeaders.AUTHORIZATION));

    }


    @Test
    public void shouldNotConnectUserWhenMissingMailInUserInfo() throws Exception {

        // -- MOCK
        //mock environment
        mockWrongEnvironment();

        //mock oauth2 exchange authorisation code for access token
        mockExchangeAuthorizationCodeForAccessToken();

        //mock oauth2 user info call
        mockUserInfo(okJson(IOUtils.toString(read("/oauth2/json/user_info_response_body.json"), Charset.defaultCharset())));

        // -- CALL

        AbstractAuthenticationResource.Payload payload = createPayload("the_client_id","http://localhost/callback","CoDe","StAtE");;

        Response response = target().request().post(json(payload));

        // -- VERIFY
        verify(userService, times(0)).findByName(anyString(), anyBoolean());
        verify(userService, times(0)).create(any());
        verify(userService, times(0)).update(any());
        verify(userService, times(0)).connect(anyString());

        assertEquals(HttpStatusCode.BAD_REQUEST_400, response.getStatus());

        // verify jwt token not present
        assertFalse(response.getCookies().containsKey(HttpHeaders.AUTHORIZATION));
    }

    private void mockUserInfo(ResponseDefinitionBuilder responseDefinitionBuilder) throws IOException {
        stubFor(
                get("/userinfo")
                        .withHeader(HttpHeaders.ACCEPT, equalTo(MediaType.APPLICATION_JSON_TYPE.toString()))
                        .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Bearer 2YotnFZFEjr1zCsicMWpAA"))
                        .willReturn(responseDefinitionBuilder));
    }

    private void mockExchangeAuthorizationCodeForAccessToken() throws IOException {
        String tokenRequestBody = ""
                + "code=CoDe&"
                + "grant_type=authorization_code&"
                + "redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&"
                + "client_secret=the_client_secret&"
                + "client_id=the_client_id";

        stubFor(
                post("/token")
                        .withHeader(HttpHeaders.ACCEPT, equalTo(MediaType.APPLICATION_JSON_TYPE.toString()))
                        .withRequestBody(equalTo(tokenRequestBody))
                    .willReturn(okJson(IOUtils.toString(read("/oauth2/json/token_response_body.json"), Charset.defaultCharset()))));
    }

    private void mockDefaultEnvironment() {
        getConfiguration().put("tokenEndpoint", "http://localhost:" + wireMockRule.port() + "/token");
        getConfiguration().put("userInfoEndpoint","http://localhost:" + wireMockRule.port() + "/userinfo");
        getConfiguration().put("accessTokenProperty","access_token");
        getConfiguration().put("authorizationHeader","Bearer %s");
        getConfiguration().put("mapping.email","email");
        getConfiguration().put("mapping.id","sub");
        getConfiguration().put("mapping.lastname","family_name");
        getConfiguration().put("mapping.firstname","given_name");
        getConfiguration().put("mapping.picture","picture");
    }

    private void mockWrongEnvironment() {
        mockDefaultEnvironment();
        getConfiguration().put("mapping.email","theEmail");
    }

    private InputStream read(String resource) throws IOException {
        return this.getClass().getResourceAsStream(resource);
    }

}
