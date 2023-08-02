package com.security.accounts.service;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;
import com.security.accounts.entity.Role;
import com.security.accounts.entity.User;
import com.security.accounts.entity.enums.RoleName;
import com.security.accounts.exception.ResourceNotFoundException;
import com.security.accounts.repository.RoleRepository;
import com.security.accounts.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
@AllArgsConstructor
public class UserServiceImpl implements UserService{

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public MessageDTO addUser(UserDTO userDTO) {
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        Set<Role> roles = new HashSet<>();
        userDTO.getRoles().forEach(r -> {
            Role role = roleRepository.findByRoleName(RoleName.valueOf(r))
                    .orElseThrow(() -> new ResourceNotFoundException("Role not found"));
            roles.add(role);
        });
        user.setRoles(roles);

        User userRegistered = userRepository.save(user);
        return new MessageDTO("User " + userRegistered.getId() + " created");
    }
}
