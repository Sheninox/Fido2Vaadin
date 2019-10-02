package de.hofmann;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

public class RegistrationStartResponse {

  enum Status {
    OK, USERNAME_TAKEN, TOKEN_INVALID
  }

  @JsonIgnore

  private final Status status;

  private final String registrationId;

  private final PublicKeyCredentialCreationOptions publicKey;

  public RegistrationStartResponse(String registrationId,
                                   PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions) {
    this.status = Status.OK;
    this.registrationId = registrationId;
    this.publicKey = publicKeyCredentialCreationOptions;
  }

  public RegistrationStartResponse(Status status) {
    this.status = status;
    this.registrationId = null;
    this.publicKey = null;
  }

  public Status getStatus() {
    return this.status;
  }

  public String getRegistrationId() {
    return this.registrationId;
  }

  public PublicKeyCredentialCreationOptions getPublicKey() {
    return this.publicKey;
  }

}