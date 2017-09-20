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

import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.el.function.JsonPathFunction;
import io.gravitee.management.model.GroupEntity;
import io.gravitee.management.model.NewExternalUserEntity;
import io.gravitee.management.model.RoleEntity;
import io.gravitee.management.model.UpdateUserEntity;
import io.gravitee.management.security.authentication.AuthenticationProvider;
import io.gravitee.management.service.GroupService;
import io.gravitee.management.service.MembershipService;
import io.gravitee.management.service.RoleService;
import io.gravitee.management.service.exceptions.UserNotFoundException;
import io.gravitee.repository.management.model.MembershipReferenceType;
import io.gravitee.repository.management.model.RoleScope;
import io.swagger.annotations.Api;
import org.glassfish.jersey.internal.util.collection.MultivaluedStringMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.util.StringUtils;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.Valid;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author GraviteeSource Team
 */
@Path("/auth/oauth2")
@Api(tags = {"Authentication"})
public class OAuth2AuthenticationResource extends AbstractAuthenticationResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2AuthenticationResource.class);

    @Inject
    @Named("oauth2")
    private AuthenticationProvider authenticationProvider;

    @Autowired
    private GroupService groupService;

    @Autowired
    private RoleService roleService;

    @Autowired
    protected MembershipService membershipService;

    private Client client;

    public OAuth2AuthenticationResource() {
        this.client = ClientBuilder.newClient();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response oauth2(@Valid final Payload payload) throws IOException {
        // Step 1. Exchange authorization code for access token.
        final MultivaluedStringMap accessData = new MultivaluedStringMap();
        accessData.add(CLIENT_ID_KEY, payload.getClientId());
        accessData.add(REDIRECT_URI_KEY, payload.getRedirectUri());
        accessData.add(CLIENT_SECRET, (String) authenticationProvider.configuration().get("clientSecret"));
        accessData.add(CODE_KEY, payload.getCode());
        accessData.add(GRANT_TYPE_KEY, AUTH_CODE);
        Response response = client.target((String) authenticationProvider.configuration().get("tokenEndpoint"))
                .request(javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.form(accessData));
        accessData.clear();

        // Step 2. Retrieve profile information about the current user.
        final String accessToken = (String) getResponseEntity(response).get(
                (String) authenticationProvider.configuration().get("accessTokenProperty"));
        response = client
                .target((String) authenticationProvider.configuration().get("userInfoEndpoint"))
                .request(javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE)
                .header(HttpHeaders.AUTHORIZATION,
                        String.format(
                                (String) authenticationProvider.configuration().get("authorizationHeader"),
                                accessToken))
                .get();

        // Step 3. Process the authenticated user.
        final String userInfo = getResponseEntityAsString(response);
        if (response.getStatus() == Response.Status.OK.getStatusCode()) {
            return processUser(userInfo);
        }

        return Response.status(response.getStatusInfo()).build();
    }

    private Response processUser(String userInfo)  throws IOException {

        Map<String, Object> userInfosAsMap = getEntity(userInfo);

        String username = (String) userInfosAsMap.get(authenticationProvider.configuration().get("mapping.email"));

        if (username == null) {
            throw new BadRequestException("No public email linked to your account");
        }

        try {
            userService.findByName(username, false);
        } catch (UserNotFoundException unfe) {

            final NewExternalUserEntity newUser = new NewExternalUserEntity();
            newUser.setUsername(username);
            newUser.setSource(AuthenticationSource.OAUTH2.getName());
            newUser.setSourceId((String) userInfosAsMap.get(authenticationProvider.configuration().get("mapping.id")));
            newUser.setLastname((String) userInfosAsMap.get(authenticationProvider.configuration().get("mapping.lastname")));
            newUser.setFirstname((String) userInfosAsMap.get(authenticationProvider.configuration().get("mapping.firstname")));
            newUser.setEmail(username);

            List<Mapping> mappings = getGroupsMappings(authenticationProvider.configuration());

            if(mappings.isEmpty()) {
                userService.create(newUser, true);
            } else {
                //can fail if a group in config does not exist in gravitee --> HTTP 500
                List<GroupEntity> groupsToAdd = getGroupsToAddUser(mappings, userInfo);

                userService.create(newUser, false);

                addUserToApiAndAppGroupsWithDefaultRole(newUser, groupsToAdd);
            }
        }

        // User refresh
        UpdateUserEntity user = new UpdateUserEntity();
        user.setUsername(username);
        user.setPicture((String) userInfosAsMap.get(authenticationProvider.configuration().get("mapping.picture")));

        userService.update(user);

        return connectUser(username);
    }

    private void addUserToApiAndAppGroupsWithDefaultRole(NewExternalUserEntity newUser, List<GroupEntity> groupsToAdd) {
        List<RoleEntity> roleEntities = roleService.findDefaultRoleByScopes(RoleScope.API,RoleScope.APPLICATION);

        //add groups to user
        for(GroupEntity groupEntity : groupsToAdd) {
            for(RoleEntity roleEntity : roleEntities) {
                membershipService.addOrUpdateMember(MembershipReferenceType.GROUP, groupEntity.getId(), newUser.getUsername(), mapScope(roleEntity.getScope()), roleEntity.getName());
            }
        }
    }

    private List<GroupEntity> getGroupsToAddUser(List<Mapping> mappings, String userInfo) {
        List<GroupEntity> groupsToAdd = new ArrayList<>();

        for (Mapping mapping: mappings) {

            Map<String, Object> variables = new HashMap<>();

            variables.put("profile",userInfo);

            final StandardEvaluationContext context = new StandardEvaluationContext();
            context.registerFunction("jsonPath", BeanUtils.resolveSignature("evaluate", JsonPathFunction.class));
            context.setVariables(variables);

            boolean match = mapping.getCondition().getValue(context, boolean.class);


            //get groups
            if(match) {
                for(String groupName : mapping.getGroupNames()) {
                    List<GroupEntity> groupEntities = groupService.findByName(groupName);

                    if(groupEntities.isEmpty()) {
                        LOGGER.error("Unable to create oauth2 user, missing group : {}", groupName);
                        throw new InternalServerErrorException();
                    } else if (groupEntities.size() > 1) {
                        LOGGER.warn("There's more than a group found for name : {}", groupName);
                    }

                    GroupEntity groupEntity = groupEntities.get(0);
                    groupsToAdd.add(groupEntity);
                }
            }
        }
        return groupsToAdd;
    }

    private RoleScope mapScope(io.gravitee.management.model.permissions.RoleScope scope) {
        if(io.gravitee.management.model.permissions.RoleScope.API == scope) {
            return RoleScope.API;
        } else {
            return RoleScope.APPLICATION;
        }
    }

    private List<Mapping> getGroupsMappings(Map<String, Object> configuration) {

        ExpressionParser parser = new SpelExpressionParser();
        List<Mapping> result = new ArrayList<>();

        int idx = 0;
        boolean found = true;

        while(found) {

            String path = "groups[" + idx + "].mapping";
            String condition = (String) configuration.get(path +".condition");

            if(!StringUtils.isEmpty(condition)) {

                Expression expr;
                try {
                    expr = parser.parseExpression(condition.trim());
                } catch (ParseException pe) {
                    LOGGER.error("Error when parsing group mapping configuration",pe);
                    throw new InternalServerErrorException();
                }

                List<String> groupNames = parseGroupNames(configuration, path);

                Mapping mapping = new Mapping(expr,groupNames);
                result.add(mapping);
                idx++;
            } else {
                found = false;
            }
        }

        return result;
    }

    private List<String> parseGroupNames(Map<String, Object> configuration, String path) {

        List<String> result = new ArrayList<>();

        int idx = 0;
        boolean found = true;

        while(found) {
            String groupName = (String)configuration.get(path + ".values[" + idx + "]");
            if(!StringUtils.isEmpty(groupName)) {
                result.add(groupName.trim());
                idx++;
            } else {
                found = false;
            }
        }

        return result;
    }



    private static final class Mapping {
        private Expression condition;
        private List<String> groupNames;

        public Mapping(Expression condition, List<String> groupNames) {
            this.condition = condition;
            this.groupNames = groupNames;
        }

        public Expression getCondition() {
            return condition;
        }

        public List<String> getGroupNames() {
            return groupNames;
        }
    }
}
