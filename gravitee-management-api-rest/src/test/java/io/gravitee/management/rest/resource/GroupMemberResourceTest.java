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
package io.gravitee.management.rest.resource;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.management.model.GroupEntity;
import io.gravitee.management.model.MemberEntity;
import io.gravitee.management.model.MemberRoleEntity;
import io.gravitee.management.model.RoleEntity;
import io.gravitee.repository.management.model.Membership;
import io.gravitee.repository.management.model.MembershipReferenceType;
import io.gravitee.repository.management.model.RoleScope;
import org.junit.Test;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

/**
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com) 
 * @author GraviteeSource Team
 */
public class GroupMemberResourceTest extends AbstractResourceTest {

    private static final String GROUP_ID = "group-id";
    private static final String USERNAME = "user";
    private static final String DEFAULT_API_ROLE = "DEFAULT_API_ROLE";
    private static final String DEFAULT_APPLICATION_ROLE = "DEFAULT_APPLICATION_ROLE";

    @Override
    protected String contextPath() {
        return "configuration/groups/"+GROUP_ID+"/members/"+USERNAME;
    }

    //ADD

    private void initADDmock() {
        reset(roleService, groupService, membershipService);
        when(groupService.findById(GROUP_ID)).thenReturn(mock(GroupEntity.class));
        when(membershipService.getMember(any(), any(), any(), any())).thenReturn(null);
        RoleEntity defaultApiRole = mock(RoleEntity.class);
        when(defaultApiRole.getName()).thenReturn(DEFAULT_API_ROLE);
        RoleEntity defaultApplicationRole = mock(RoleEntity.class);
        when(defaultApplicationRole.getName()).thenReturn(DEFAULT_APPLICATION_ROLE);
        when(roleService.findDefaultRoleByScopes(RoleScope.API)).thenReturn(Collections.singletonList(defaultApiRole));
        when(roleService.findDefaultRoleByScopes(RoleScope.APPLICATION)).thenReturn(Collections.singletonList(defaultApplicationRole));
        MemberEntity memberEntity = new MemberEntity();
        memberEntity.setUsername(USERNAME);
        when(membershipService.addOrUpdateMember(any(), any(), any(), any(), any())).thenReturn(memberEntity);
    }

    @Test
    public void shouldAddMemberWithCustomApplicationRoleAndCustomApiRole() {
        initADDmock();
        MemberRoleEntity apiRole = new MemberRoleEntity();
        apiRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.API);
        apiRole.setRoleName("CUSTOM_API");
        MemberRoleEntity appRole = new MemberRoleEntity();
        appRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.APPLICATION);
        appRole.setRoleName("CUSTOM_APP");

        final Response response = target().request().put(Entity.json(Arrays.asList(apiRole, appRole)));

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.API);
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.APPLICATION);
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.API, "CUSTOM_API");
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.APPLICATION, "CUSTOM_APP");
    }

    //UPDATE
    private void initUPDATEmock() {
        reset(roleService, groupService, membershipService);
        when(groupService.findById(GROUP_ID)).thenReturn(mock(GroupEntity.class));
        when(membershipService.getMember(any(), any(), any(), any())).thenReturn(new MemberEntity());
    }

    @Test
    public void shouldUpdateNothing() {
        initUPDATEmock();

        final Response response = target().request().put(Entity.json(Collections.emptyList()));

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.API);
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.APPLICATION);
        verify(membershipService, never()).addOrUpdateMember(any(), any(), any(), any(), any());
    }

    @Test
    public void shouldUpdateApiRole() {
        initUPDATEmock();

        MemberRoleEntity apiRole = new MemberRoleEntity();
        apiRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.API);
        apiRole.setRoleName("CUSTOM");
        final Response response = target().request().put(Entity.json(Collections.singleton(apiRole)));

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.API);
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.APPLICATION);
        verify(membershipService, times(1)).addOrUpdateMember(any(), any(), any(), any(), any());
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.API, "CUSTOM");
    }

    @Test
    public void shouldUpdateApplicationRole() {
        initUPDATEmock();

        MemberRoleEntity appRole = new MemberRoleEntity();
        appRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.APPLICATION);
        appRole.setRoleName("CUSTOM");
        final Response response = target().request().put(Entity.json(Collections.singleton(appRole)));

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.API);
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.APPLICATION);
        verify(membershipService, times(1)).addOrUpdateMember(any(), any(), any(), any(), any());
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.APPLICATION, "CUSTOM");
    }

    @Test
    public void shouldUpdateApiAndApplicationRole() {
        initUPDATEmock();
        MemberRoleEntity apiRole = new MemberRoleEntity();
        apiRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.API);
        apiRole.setRoleName("CUSTOM_API");
        MemberRoleEntity appRole = new MemberRoleEntity();
        appRole.setRoleScope(io.gravitee.management.model.permissions.RoleScope.APPLICATION);
        appRole.setRoleName("CUSTOM_APP");

        final Response response = target().request().put(Entity.json(Arrays.asList(apiRole, appRole)));

        assertEquals(HttpStatusCode.OK_200, response.getStatus());
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.API);
        verify(roleService, never()).findDefaultRoleByScopes(RoleScope.APPLICATION);
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.API, "CUSTOM_API");
        verify(membershipService, times(1))
                .addOrUpdateMember(MembershipReferenceType.GROUP, GROUP_ID, USERNAME, RoleScope.APPLICATION, "CUSTOM_APP");
    }
}
