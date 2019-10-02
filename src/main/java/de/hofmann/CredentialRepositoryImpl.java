package de.hofmann;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;

import java.util.*;

public class CredentialRepositoryImpl implements CredentialRepository {
    private Collection<User> userCollection = new ArrayList<>();
    private Collection<RegisteredCredential> credentialCollection = new ArrayList<>();

    void addCredential(long userId, byte[] credentialId, byte[] publicKeyCose, long counter){
        RegisteredCredential credential = RegisteredCredential.builder()
                .credentialId(new ByteArray(credentialId))
                .userHandle(new ByteArray(BytesUtil.longToBytes(userId)))
                .publicKeyCose(new ByteArray(publicKeyCose))
                .signatureCount(counter).build();

        credentialCollection.add(credential);
    }

    void addUser(User user){
        userCollection.add(user);
    }

    User getUserbyUsername(String username){
        for (User user : userCollection) {
            if (user.getUsername().equals(username)) {
                return user;
            }
        }
        return null;
    }

    long getNextId(){
        long id = 0;
        for (User user : userCollection) {
            if(user.getId()>= id){
                id = user.getId()+1;
            }

        }
        return id;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String s) {
        Set<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = new HashSet<>();
        userCollection.forEach(user -> {
            if (user.getUsername().equals(s)){
                credentialCollection.forEach(registeredCredential -> {
                    if (BytesUtil.bytesToLong(registeredCredential.getUserHandle().getBytes()) == user.getId()){
                        publicKeyCredentialDescriptors.add(PublicKeyCredentialDescriptor.builder()
                                .id(registeredCredential.getCredentialId())
                                .type(PublicKeyCredentialType.PUBLIC_KEY).build());
                    }
                });
            }
        });
        return publicKeyCredentialDescriptors;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String s) {
        for (User user : userCollection) {
            if (user.getUsername().equals(s)) {
                return Optional.of(new ByteArray(BytesUtil.longToBytes(user.getId())));
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        for (User user : userCollection) {
            if (user.getId() == BytesUtil.bytesToLong(userHandle.getBytes())) {
                return Optional.of(user.getUsername());
            }
        }
        return Optional.empty();
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId,
                                                 ByteArray userHandle) {

        for (RegisteredCredential credential : credentialCollection){
            if (credential.getUserHandle().equals(userHandle)  && credential.getCredentialId().equals(credentialId) ){
                return Optional.of(credential);
            }
        }
        return Optional.empty();
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray userHandle) {
        Set<RegisteredCredential> registeredCredentials = new HashSet<>();
        for (RegisteredCredential credential : credentialCollection){
            if (credential.getUserHandle() == userHandle){
                registeredCredentials.add(credential);
            }
        }
        return registeredCredentials;
    }

    boolean updateSignatureCount(AssertionResult result) {
        for (RegisteredCredential credential : credentialCollection){
            if (credential.getCredentialId().equals(result.getCredentialId())){
                credentialCollection.remove(credential);
                this.addCredential(BytesUtil.bytesToLong(credential.getUserHandle().getBytes()),
                        credential.getCredentialId().getBytes(),
                        credential.getPublicKeyCose().getBytes(),
                        result.getSignatureCount());
                return true;
            }
        }
        return false;
    }
}
