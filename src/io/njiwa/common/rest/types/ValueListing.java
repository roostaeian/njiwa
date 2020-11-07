package io.njiwa.common.rest.types;

import java.util.ArrayList;
import java.util.List;

/**
 * @brief represents a list of values for use in tables by the UI
 */
public class ValueListing {
    public String[] headers; //<! The headings for the table
    public List<Object[]> rows = new ArrayList<>();

    public ValueListing() {}
    public ValueListing(String[] headers)
    {
        this.headers = headers;
    }

    public void addRow(Object[] data) throws  Exception
    {
        if (headers.length != data.length)
            throw new Exception(String.format("Invalid number of columns, must be: %s", headers.length));
        if (rows == null)
            rows = new ArrayList<>();
        rows.add(data);
    }
}
