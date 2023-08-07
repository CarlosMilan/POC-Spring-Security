package com.security.accounts.service;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;

public interface UserService {

    UserDTO getUserDetails(String username);
    MessageDTO createUser(UserDTO userDTO);
    MessageDTO updateUser(UserDTO userDTO);
    MessageDTO deleteUser(String id);
}
