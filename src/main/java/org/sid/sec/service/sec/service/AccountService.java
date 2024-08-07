package org.sid.sec.service.sec.service;

import org.sid.sec.service.sec.entities.AppRole;
import org.sid.sec.service.sec.entities.AppUser;

import java.util.List;

public interface AccountService  {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username,String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
