package de.hofmann;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

public class AssertionStartResponse {

  private final String assertionId;

  private final PublicKeyCredentialRequestOptions publicKey;

  @JsonIgnore
  private final AssertionRequest assertionRequest;

  public AssertionStartResponse(String assertionId, AssertionRequest assertionRequest) {
    this.assertionId = assertionId;
    this.publicKey = assertionRequest
        .getPublicKeyCredentialRequestOptions();
    this.assertionRequest = assertionRequest;
  }

  public String getAssertionId() {
    return this.assertionId;
  }

  public PublicKeyCredentialRequestOptions getPublicKey() {
    return this.publicKey;
  }

  public AssertionRequest getAssertionRequest() {
    return this.assertionRequest;
  }

}
