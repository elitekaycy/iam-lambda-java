package com.iam;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.secretsmanager.*;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.simplesystemsmanagement.*;
import com.amazonaws.services.simplesystemsmanagement.model.GetParameterRequest;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.util.Map;

public class IAMUserCreationLoggerHandler implements RequestHandler<Map<String, Object>, String> {

  private final AWSSecretsManager secretsClient = AWSSecretsManagerClientBuilder.defaultClient();
  private final AWSSimpleSystemsManagement ssmClient =
      AWSSimpleSystemsManagementClientBuilder.defaultClient();
  private final Gson gson = new Gson();

  @Override
  @SuppressWarnings("unchecked")
  public String handleRequest(Map<String, Object> event, Context context) {
    final LambdaLogger logger = context.getLogger();

    try {
      logger.log("Raw event: " + event + "\n");

      if (event == null) {
        logger.log("ERROR: Null event received\n");
        return "Error: Null event";
      }

      Map<String, Object> detail = (Map<String, Object>) event.get("detail");
      if (detail == null) {
        logger.log("ERROR: Missing 'detail' in event\n");
        return "Error: Missing detail";
      }

      Map<String, Object> requestParameters = (Map<String, Object>) detail.get("requestParameters");
      if (requestParameters == null) {
        logger.log("ERROR: Missing requestParameters\n");
        return "Error: Missing requestParameters";
      }

      String username;
      Object userNameObj = requestParameters.get("userName");

      if (userNameObj instanceof Map) {
        username = ((Map<String, String>) userNameObj).get("userName");
      } else if (userNameObj instanceof String) {
        username = (String) userNameObj;
      } else {
        logger.log("ERROR: Unexpected userName type: " + userNameObj.getClass() + "\n");
        return "Error: Invalid userName format";
      }

      if (username == null || username.isEmpty()) {
        logger.log("ERROR: Empty username\n");
        return "Error: Empty username";
      }

      String paramPath = "/iam/users/" + username + "/email";
      String email =
          ssmClient
              .getParameter(new GetParameterRequest().withName(paramPath).withWithDecryption(true))
              .getParameter()
              .getValue();

      String secret =
          secretsClient
              .getSecretValue(
                  new GetSecretValueRequest().withSecretId("iam-users-temporary-password"))
              .getSecretString();

      String password = gson.fromJson(secret, JsonObject.class).get("password").getAsString();

      logger.log(
          String.format(
              "Successfully processed user creation\n"
                  + "Username: %s\n"
                  + "Email: %s\n"
                  + "Temporary Password: %s",
              username, email, password));

      return "Success";

    } catch (Exception e) {
      logger.log("ERROR: " + e.toString() + "\n");
      for (StackTraceElement element : e.getStackTrace()) {
        logger.log(element.toString() + "\n");
      }
      return "Failure: " + e.getMessage();
    }
  }
}
