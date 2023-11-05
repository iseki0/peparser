package space.iseki.peparser;

public class PEFileException extends RuntimeException {
    private static final String DEFAULT_MESSAGE = "reading PE file failed";

    public PEFileException(String message) {
        super(message);
    }

    public PEFileException(String message, Throwable cause) {
        super(message, cause);
    }

    public PEFileException(Throwable cause) {
        super(DEFAULT_MESSAGE, cause);
    }
}
