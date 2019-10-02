package de.hofmann;

public class User {

    private long id;
    private String username;

    long getId() {
        return id;
    }

    String getUsername() {
        return username;
    }

    User(long id, String username) {
        this.id = id;
        this.username = username;
    }
}
