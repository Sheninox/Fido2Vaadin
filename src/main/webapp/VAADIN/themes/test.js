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

function registerUser(publicKeyString){
    var publicKey = JSON.parse(publicKeyString);
    publicKey.challenge = bufferDecode(publicKey.challenge);
    publicKey.user.id = bufferDecode(publicKey.user.id);
    if (publicKey.excludeCredentials) {
        for (var i = 0; i < publicKey.excludeCredentials.length; i++) {
            publicKey.excludeCredentials[i].id = bufferDecode(publicKey.excludeCredentials[i].id);
        }
    }
    navigator.credentials.create({
        publicKey: publicKey
    }).then(function(credential){
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
    })
}
function registerSuccess(username) {
        alert("successfully registered " + username + "!");
}

function loginCredentialRequest(requestString) {
    var request = JSON.parse(requestString);
    request.publicKeyCredentialRequestOptions.challenge = bufferDecode(request.publicKeyCredentialRequestOptions.challenge);
    request.publicKeyCredentialRequestOptions.allowCredentials.forEach(function (item) {
        item.id = bufferDecode(item.id)
    });
    navigator.credentials.get({
        publicKey: request.publicKeyCredentialRequestOptions
    }).then(function(assertion){
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
    });
}

function loginSuccess(username) {
    alert("successfully logged in " + username + "!")

}
