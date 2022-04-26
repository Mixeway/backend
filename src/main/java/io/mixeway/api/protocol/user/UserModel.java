package io.mixeway.api.protocol.user;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.Optional;

@Getter
@Setter
@Builder
@NoArgsConstructor
public class UserModel {
    String userRole;
    String userCN;
    Boolean passwordAuth;
    String userPassword;
    String userUsername;
    String apiKey;
    Optional<List<Long>> projects;

}
