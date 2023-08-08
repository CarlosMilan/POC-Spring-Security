package com.security.accounts.service;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;
import com.security.accounts.dto.UserResponseDTO;
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
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Transactional
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public UserResponseDTO getUserDetails(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        return UserResponseDTO.builder()
                .id(user.getId().toString())
                .username(user.getUsername())
                .roles(user.getRoles()
                        .stream()
                        .map(role -> role.getRoleName().toString())
                        .collect(Collectors.toSet()))
                .build();
    }

    @Override
    public MessageDTO createUser(UserDTO userDTO) {
        User user = saveUser(new User(), userDTO);
        return new MessageDTO("User " + user.getId() + " created");
    }

    @Override
    public MessageDTO updateUser(UserDTO userDTO) {
        User user = userRepository.findById(UUID.fromString(userDTO.getId()))
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        saveUser(user, userDTO);
        return new MessageDTO("User " + user.getUsername() + " updated");
    }

    private User saveUser(User user, UserDTO userDTO) {

        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        Set<Role> roles = new HashSet<>();
        userDTO.getRoles().forEach(r -> {
            Role role = roleRepository.findByRoleName(RoleName.valueOf(r))
                    .orElseThrow(() -> new ResourceNotFoundException("Role not found"));
            roles.add(role);
        });
        user.setRoles(roles);
        return userRepository.save(user);
    }

    @Override
    public MessageDTO deleteUser(String id) {
        userRepository.deleteById(UUID.fromString(id));
        return new MessageDTO("User " + id + " deleted");
    }


}
