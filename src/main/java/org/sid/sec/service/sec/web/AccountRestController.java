package org.sid.sec.service.sec.web;

import lombok.Data;
import org.sid.sec.service.sec.entities.AppRole;
import org.sid.sec.service.sec.entities.AppUser;
import org.sid.sec.service.sec.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
@GetMapping(path = "/users")
@PostAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers(){
return accountService.listUsers();
    }
    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    AppUser saveUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    AppRole saveUser(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
          accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRoleName());
    }
}
@Data
class RoleUserForm{
    private String username;
    private String roleName;
}