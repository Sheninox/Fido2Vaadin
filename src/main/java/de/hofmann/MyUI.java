package de.hofmann;

import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.vaadin.annotations.JavaScript;
import com.vaadin.annotations.Theme;
import com.vaadin.annotations.VaadinServletConfiguration;
import com.vaadin.server.VaadinRequest;
import com.vaadin.server.VaadinServlet;
import com.vaadin.ui.*;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.annotation.WebServlet;
import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.security.SecureRandom;
import java.util.*;

@JavaScript("vaadin://themes/test.js")
@Theme("mytheme")
public class MyUI extends UI {

    private RelyingParty relyingParty;
    private SecureRandom random = new SecureRandom();
    private RegistrationStartResponse registrationStartResponse;
    private AssertionStartResponse assertionStartResponse;
    private CredentialRepositoryImpl credentialRepository = new CredentialRepositoryImpl();
    private GsonBuilder gsonBuilder = new GsonBuilder();

    @Override
    protected void init(VaadinRequest vaadinRequest) {
        final VerticalLayout layout = new VerticalLayout();
        TextField usernameField = new TextField("Username");

        gsonBuilder.registerTypeAdapter(ByteArray.class, new TypeAdapter<ByteArray>() {
            @Override
            public void write(JsonWriter jsonWriter, ByteArray byteArray) throws IOException {
                String base64EncodedChallange = Base64.getEncoder().encodeToString(byteArray.getBytes());
                jsonWriter.value(base64EncodedChallange);
            }

            @Override
            public ByteArray read(JsonReader jsonReader) {
                return null;
            }
        });
        gsonBuilder.registerTypeAdapter(PublicKeyCredentialType.class, new TypeAdapter<PublicKeyCredentialType>() {
            @Override
            public void write(JsonWriter jsonWriter, PublicKeyCredentialType publicKeyCredentialType) throws IOException {
                jsonWriter.value(publicKeyCredentialType.toJsonString());
            }

            @Override
            public PublicKeyCredentialType read(JsonReader jsonReader) {
                return null;
            }
        });
        gsonBuilder.registerTypeAdapter(COSEAlgorithmIdentifier.class, new TypeAdapter<COSEAlgorithmIdentifier>() {
            @Override
            public void write(JsonWriter jsonWriter, COSEAlgorithmIdentifier coseAlgorithmIdentifier) throws IOException {
                jsonWriter.value(Long.toString(coseAlgorithmIdentifier.toJsonNumber()));
            }

            @Override
            public COSEAlgorithmIdentifier read(JsonReader jsonReader) {
                return null;
            }

        });
        gsonBuilder.registerTypeAdapter(AuthenticatorTransport.class, new TypeAdapter<AuthenticatorTransport>() {
            @Override
            public void write(JsonWriter jsonWriter, AuthenticatorTransport authenticatorTransport) throws IOException {
                jsonWriter.value(authenticatorTransport.toJsonString());
            }

            @Override
            public AuthenticatorTransport read(JsonReader jsonReader) {
                return null;
            }

        });
        gsonBuilder.registerTypeAdapter(AttestationConveyancePreference.class, new TypeAdapter<AttestationConveyancePreference>() {
            @Override
            public void write(JsonWriter jsonWriter, AttestationConveyancePreference attestationConveyancePreference) throws IOException {
                jsonWriter.value(attestationConveyancePreference.toJsonString());
            }

            @Override
            public AttestationConveyancePreference read(JsonReader jsonReader) {
                return null;
            }

        });
        gsonBuilder.registerTypeAdapter(UserVerificationRequirement.class, new TypeAdapter<UserVerificationRequirement>() {
            @Override
            public void write(JsonWriter jsonWriter, UserVerificationRequirement userVerificationRequirement) throws IOException {
                jsonWriter.value(userVerificationRequirement.toJsonString());
            }

            @Override
            public UserVerificationRequirement read(JsonReader jsonReader) {
                return null;
            }

        });
        gsonBuilder.registerTypeAdapter(Optional.class, new OptionalAdapter());

        Set<String> origins = new HashSet<>();
        origins.add("http://localhost:8080");
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("localhost:8080").build();
        this.relyingParty = RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialRepository).origins(origins).build();

        com.vaadin.ui.JavaScript.getCurrent().addFunction("registerFinish",
                (JavaScriptFunction) arguments -> {
                    try {

                        try {
                            JSONObject jsonObject = new JSONObject(arguments.getString(0));
                            JSONObject response = jsonObject.getJSONObject("response");

                            AuthenticatorAttestationResponse authenticatorAttestationResponse = AuthenticatorAttestationResponse.builder()
                                    .attestationObject(ByteArray.fromBase64(response.getString("attestationObject")))
                                    .clientDataJSON(ByteArray.fromBase64(response.getString("clientDataJSON")))
                                    .build();



                            PublicKeyCredential cred = PublicKeyCredential.builder()
                                    .id(ByteArray.fromBase64(jsonObject.getString("id")))
                                    .response(authenticatorAttestationResponse)
                                    .clientExtensionResults(
                                            ClientRegistrationExtensionOutputs.builder().build())
                                    .type(PublicKeyCredentialType.PUBLIC_KEY).build();

                            RegistrationFinishRequest finishRequest = new RegistrationFinishRequest("" , cred);

                            if (registrationStartResponse != null) {
                                try {
                                    RegistrationResult registrationResult = this.relyingParty
                                            .finishRegistration(FinishRegistrationOptions.builder()
                                                    .request(registrationStartResponse.getPublicKey())
                                                    .response(finishRequest.getCredential()).build());

                                    UserIdentity userIdentity = registrationStartResponse.getPublicKey()
                                            .getUser();

                                    long userId = BytesUtil.bytesToLong(userIdentity.getId().getBytes());

                                        this.credentialRepository.addCredential(userId,
                                            registrationResult.getKeyId().getId().getBytes(),
                                            registrationResult.getPublicKeyCose().getBytes(),
                                            finishRequest.getCredential().getResponse().getParsedAuthenticatorData()
                                                    .getSignatureCounter());

                                        registrationStartResponse = null;
                                        com.vaadin.ui.JavaScript.getCurrent().execute("registerSuccess(\'"+userIdentity.getDisplayName()+"\')");

                                } catch (RegistrationFailedException e) {
                                    e.printStackTrace();
                                    System.out.println(e.getMessage());
                                }
                            }
                            } catch (JSONException err) {
                                    err.printStackTrace();
                            }

                    } catch (Exception e) {
                        Notification.show("Error: " + e.getMessage());
                    }
                });

        com.vaadin.ui.JavaScript.getCurrent().addFunction("loginFinish",
                (JavaScriptFunction) arguments -> {
                    try {
                        JSONObject jsonObject = new JSONObject(arguments.getString(0));
                        JSONObject response = jsonObject.getJSONObject("response");

                        AuthenticatorAssertionResponse authenticatorAttestationResponse = AuthenticatorAssertionResponse.builder()
                                .authenticatorData(ByteArray.fromBase64(response.getString("authenticatorData")))
                                .clientDataJSON(ByteArray.fromBase64(response.getString("clientDataJSON")))
                                .signature(ByteArray.fromBase64(response.getString("signature")))
                                .build();

                        PublicKeyCredential cred = PublicKeyCredential.builder()
                                .id(ByteArray.fromBase64(jsonObject.getString("id")))
                                .response(authenticatorAttestationResponse)
                                .clientExtensionResults(
                                        ClientRegistrationExtensionOutputs.builder().build())
                                .type(PublicKeyCredentialType.PUBLIC_KEY).build();

                        AssertionFinishRequest finishRequest = new AssertionFinishRequest(jsonObject.getString("id"), cred);

                        try {
                            AssertionResult result = this.relyingParty.finishAssertion(
                                    FinishAssertionOptions.builder().request(assertionStartResponse.getAssertionRequest())
                                            .response(finishRequest.getCredential()).build());

                            if (result.isSuccess()) {
                                if (!this.credentialRepository.updateSignatureCount(result)) {
                                    System.out.println("Failed to update signature count");
                                }
                                assertionStartResponse = null;
                                com.vaadin.ui.JavaScript.getCurrent().execute("loginSuccess(\'"+result.getUsername()+"\')");
                            }
                        }
                        catch (AssertionFailedException e) {
                            e.printStackTrace();
                            System.out.println(e.getMessage());
                        }

                    } catch (Exception e) {
                        Notification.show("Error: " + e.getMessage());
                    }
                });
        Button Register = new Button("Register", e ->{
            User user;
            String name = usernameField.getValue();
            if(credentialRepository.getUserbyUsername(name) == null){
                user = new User(credentialRepository.getNextId(), name);
                credentialRepository.addUser(user);
            }else {
                user = credentialRepository.getUserbyUsername(name);
            }

            PublicKeyCredentialCreationOptions credentialCreation = this.relyingParty
                    .startRegistration(StartRegistrationOptions.builder()
                            .user(UserIdentity.builder().name(name).displayName(name)
                                    .id(new ByteArray(BytesUtil.longToBytes(user.getId()))).build())
                            .build());

            byte[] registrationId = new byte[16];
            this.random.nextBytes(registrationId);
            registrationStartResponse = new RegistrationStartResponse(
                    Base64.getEncoder().encodeToString(registrationId), credentialCreation);

            Gson gson = gsonBuilder.create();
            String startResponseJson = gson.toJson(registrationStartResponse);
            com.vaadin.ui.JavaScript.getCurrent().execute("registerUser(\'"+startResponseJson+"\')");
        });
        Button Login = new Button("Login", e ->{
            String username = usernameField.getValue();

            byte[] assertionId = new byte[16];
            this.random.nextBytes(assertionId);

            assertionStartResponse = new AssertionStartResponse(
                    Base64.getEncoder().encodeToString(assertionId), this.relyingParty
                    .startAssertion(StartAssertionOptions.builder().username(username).build()));

            Gson gson = gsonBuilder.create();
            String startResponseJson = gson.toJson(assertionStartResponse);

            com.vaadin.ui.JavaScript.getCurrent().execute("loginCredentialRequest(\'"+startResponseJson+"\')");
        });
        layout.addComponents(usernameField, Register, Login);
        setContent(layout);
    }

    @WebServlet(urlPatterns = "/*", name = "MyUIServlet", asyncSupported = true)
    @VaadinServletConfiguration(ui = MyUI.class, productionMode = false)
    public static class MyUIServlet extends VaadinServlet {
    }

    private class OptionalAdapter implements JsonSerializer<Optional>, JsonDeserializer<Optional> {

        @Override
        public Optional deserialize(JsonElement jsonElement, Type typeOfT, JsonDeserializationContext context)
            throws JsonParseException {
            final Object value = context.deserialize(jsonElement, ((ParameterizedType) typeOfT).getActualTypeArguments()[0]);
            return Optional.ofNullable(value);
        }

        @Override
        public JsonElement serialize(Optional src, Type typeOfSrc, JsonSerializationContext context) {
            final JsonElement element = context.serialize(src.orElse(null));
            return element;
        }
    }
}
