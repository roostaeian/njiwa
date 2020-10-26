# Njiwa REST API Documentation

## Introduction
 Njiwa provides an [HTTP REST API](https://restfulapi.net/) to be used for quering and updating entities. It is primarily used by the Web user interface. 
 This document provides a guide to using the API. 
   
  Assuming Njiwa is deployed on your server with URI */njiwa*, the REST APIs are published at */njiwa/rest*
  
## API listing
 This section lists all the APIs exposed by Njiwa, by category
 
  All REST API responses are JSON-encoded *Response* objects, and contain the following fields:
* *status* - A response status string, which is set to *Success* or *Failed*
* *response* - An object, whose contents depends on the API called (more below);
* *errors* - In the event of an error, this is a list of error strings.

 Additional fields may be added to the response, depending on the API called.
 
 ### APIs

* *auth* - This provides API user authentication services (URI: */rest/auth* )
    - *login* - User logon API. Expects an object with two string fields: *userId* and *password*. It returns a *Response* object, 
     which may include additional fields *roles* - the list of assigned roles for the user, *realm* the user realm (more on this later), *allRoles* - the list of all system defined roles.
    - *check* - Checks if the current user is still logged on. Returns a *Response* object.
    - *logout* - Performs a session logout.
    Note that this API uses a session cookie to track session liveness. The cookie is returned on successful logon.