// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

function registerUser(credentialCreationOptionsString){
    var credentialCreationOptions = JSON.parse(credentialCreationOptionsString);
    credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
    credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
    if (credentialCreationOptions.publicKey.excludeCredentials) {
        for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
            credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
        }
    }
    credentialCreationOptions.publicKey.excludeCredentials = undefined;
    navigator.credentials.create({
        publicKey: credentialCreationOptions.publicKey
    }).then(function(data){registerCredential(data)})
}
function registerCredential(credential) {
    var attestationObject = credential.response.attestationObject;
    var clientDataJSON = credential.response.clientDataJSON;
    var rawId = credential.rawId;

    var registerString = JSON.stringify({
        id: credential.id,
        rawId: bufferEncode(rawId),
        type: credential.type,
        response: {
            attestationObject: bufferEncode(attestationObject),
            clientDataJSON: bufferEncode(clientDataJSON)
        }
    });
    registerFinish(registerString)
}
function registerSuccess(username) {
        alert("successfully registered " + username + "!");

}
function loginCredentialRequest(credentialRequestOptionsString) {
    var credentialRequestOptions = JSON.parse(credentialRequestOptionsString);
    credentialRequestOptions.publicKeyCredentialRequestOptions.challenge = bufferDecode(credentialRequestOptions.publicKeyCredentialRequestOptions.challenge);
    credentialRequestOptions.publicKeyCredentialRequestOptions.allowCredentials.forEach(function (item) {
        item.id = bufferDecode(item.id)
    });
    navigator.credentials.get({
        publicKey: credentialRequestOptions.publicKeyCredentialRequestOptions
    }).then(function(data){ loginCredential(data)});

}
function loginCredential(assertion) {
    var authData = assertion.response.authenticatorData;
    var clientDataJSON = assertion.response.clientDataJSON;
    var rawId = assertion.rawId;
    var sig = assertion.response.signature;
    var userHandle = assertion.response.userHandle;
    var losingString = JSON.stringify({
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle)
            }
        });
    loginFinish(losingString)
}

function loginSuccess(username) {
    alert("successfully logged in " + username + "!")

}
