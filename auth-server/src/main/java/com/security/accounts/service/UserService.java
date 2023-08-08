package com.security.accounts.service;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;
import com.security.accounts.dto.UserResponseDTO;

public interface UserService {

    UserResponseDTO getUserDetails(String username);
    MessageDTO createUser(UserDTO userDTO);
    MessageDTO updateUser(UserDTO userDTO);
    MessageDTO deleteUser(String id);
}
