package io.njiwa.common.rest.types;

/**
 * @brief used to inform upper layer of issues.
 */
public class RestException  extends  Exception {
    public String field; // The field that caused the error

    public RestException(String field, String message) {
        super(message);
        this.field = field;
    }
}
