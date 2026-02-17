package fr.synqkro.api.common.exception;

public class ClockBackwardsException extends RuntimeException {
    public ClockBackwardsException(String message) {
        super(message);
    }
}