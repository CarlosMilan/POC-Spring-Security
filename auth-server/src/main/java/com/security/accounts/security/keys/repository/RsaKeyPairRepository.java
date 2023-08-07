package com.security.accounts.security.keys.repository;

import com.security.accounts.security.keys.entity.RsaKeyPair;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RsaKeyPairRepository extends JpaRepository<RsaKeyPair, UUID> {

}
