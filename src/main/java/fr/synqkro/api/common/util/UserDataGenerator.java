package fr.synqkro.api.common.util;

import java.util.UUID;

public class UserDataGenerator {
    public static String generateRandomEmail() {
        return "deleted_user_" + java.util.UUID.randomUUID().toString().substring(0, 8) + "@"+ UUID.randomUUID() + ".com";
    }
    public static String generateRandomUsername() {
        return "deleted_user_" + java.util.UUID.randomUUID().toString().substring(0, 8);

    }

    public static String generateRandomPassword() {
        return "";
    }
}
