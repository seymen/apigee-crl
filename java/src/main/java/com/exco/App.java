package com.exco;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

/**
 * Hello world!
 *
 */
public class App implements Execution
{
  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      messageContext.setVariable("flow.exco.boo", "foo");
      return ExecutionResult.SUCCESS;
    } catch (Exception e) {
      return ExecutionResult.ABORT;
    }
  }
}
