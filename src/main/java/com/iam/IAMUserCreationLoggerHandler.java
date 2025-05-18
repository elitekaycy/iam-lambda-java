package com.iam;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.secretsmanager.*;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagement;
import com.amazonaws.services.simplesystemsmanagement.AWSSimpleSystemsManagementClientBuilder;
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
    // 1. Parse EventBridge event
    Map<String, Object> detail = (Map<String, Object>) event.get("detail");
    String username =
        ((Map<String, String>)
                ((Map<String, Object>) detail.get("requestParameters")).get("userName"))
            .get("userName");

    try {
      // 2. Get email from SSM (dynamic path based on username)
      String email =
          ssmClient
              .getParameter(new GetParameterRequest().withName("/iam/users/" + username + "/email"))
              .getParameter()
              .getValue();

      // 3. Get password from Secrets Manager
      String secret =
          secretsClient
              .getSecretValue(
                  new GetSecretValueRequest().withSecretId("iam-users-temporary-password"))
              .getSecretString();

      String password = gson.fromJson(secret, JsonObject.class).get("password").getAsString();

      // 4. Log results (mask password in production!)
      System.out.printf(
          "New user: %s | Email: %s | Temp Password: %s%n", username, email, password);

      return "Success";
    } catch (Exception e) {
      throw new RuntimeException("Failed to process user creation", e);
    }
  }
}
