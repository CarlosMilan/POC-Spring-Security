package com.security.accounts.service;

import com.security.accounts.dto.MessageDTO;
import com.security.accounts.dto.UserDTO;

public interface UserService {
    MessageDTO addUser(UserDTO userDTO);
}
