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
package io.gravitee.management.rest.resource.auth.oauth2;

import io.gravitee.el.SpelTemplateEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.util.StringUtils;

import javax.ws.rs.InternalServerErrorException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by Christophe on 26/09/2017.
 */
public class ServerConfigurationParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServerConfigurationParser.class);


    public ServerConfiguration parseConfiguration(Map<String, Object> configuration) {

        ServerConfiguration serverConfiguration = parseServerConfiguration(configuration);
        serverConfiguration.setGroupsMapping(getGroupsMappings(configuration));
        serverConfiguration.setUserMapping(parseUserMapping(configuration));

        return serverConfiguration;
    }

    private ServerConfiguration parseServerConfiguration(Map<String, Object> configuration) {

        ServerConfiguration serverConfiguration = new ServerConfiguration();
        serverConfiguration.setClientSecret((String)configuration.get("clientSecret"));
        serverConfiguration.setTokenEndpoint((String)configuration.get("tokenEndpoint"));
        serverConfiguration.setAccessTokenProperty((String)configuration.get("accessTokenProperty"));
        serverConfiguration.setUserInfoEndpoint((String)configuration.get("userInfoEndpoint"));
        serverConfiguration.setAuthorizationHeader((String)configuration.get("authorizationHeader"));

        return serverConfiguration;
    }


    private UserMapping parseUserMapping(Map<String, Object> configuration) {

        UserMapping userMapping = new UserMapping();
        userMapping.setEmail((String)configuration.get("mapping.email"));
        userMapping.setId((String)configuration.get("mapping.id"));
        userMapping.setLastname((String)configuration.get("mapping.lastname"));
        userMapping.setFirstname((String)configuration.get("mapping.firstname"));
        userMapping.setPicture((String)configuration.get("mapping.picture"));

        return userMapping;
    }


    private List<ExpressionMapping> getGroupsMappings(Map<String, Object> configuration) {

        SpelTemplateEngine spelTemplateEngine = new SpelTemplateEngine();
        List<ExpressionMapping> result = new ArrayList<>();

        int idx = 0;
        boolean found = true;

        while(found) {

            String path = "groups[" + idx + "].mapping";
            String condition = (String) configuration.get(path +".condition");

            if(!StringUtils.isEmpty(condition)) {

                Expression expr;
                try {
                    expr = spelTemplateEngine.parseExpression(condition.trim());
                } catch (ParseException pe) {
                    LOGGER.error("Error when parsing group mapping configuration",pe);
                    throw new InternalServerErrorException();
                }

                List<String> groupNames = parseGroupNames(configuration, path);

                ExpressionMapping mapping = new ExpressionMapping(expr,groupNames);

                if(LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Expression {} give groups {}", condition, groupNames.toString());
                }

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

}
