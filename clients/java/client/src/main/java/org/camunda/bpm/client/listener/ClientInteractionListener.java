package org.camunda.bpm.client.listener;

import org.camunda.bpm.client.impl.EngineClientException;
import org.camunda.bpm.client.task.ExternalTask;
import org.camunda.bpm.client.topic.impl.dto.TopicRequestDto;

import java.util.List;
import java.util.Map;

public interface ClientInteractionListener {

     void onFetchAndLock(List<TopicRequestDto> topics);
     void fetchAndLockDone(List<TopicRequestDto> topics, List<ExternalTask> externalTasks);
     void fetchAndLockFail(List<TopicRequestDto> topics, EngineClientException e);

     void onUnlock(String taskId);
     void unlockDone(String taskId);
     void unlockFail(String taskId, EngineClientException e);

     void onSetVariable(String processInstanceId, Map<String, Object> variables);
     void setVariableDone(String processInstanceId, Map<String, Object> variables);
     void setVariableFail(String processInstanceId, Map<String, Object> variables, EngineClientException e);

     void onComplete(String taskId, Map<String, Object> variables, Map<String, Object> localVariables);
     void completeDone(String taskId, Map<String, Object> variables, Map<String, Object> localVariables);
     void completeFail(String taskId, Map<String, Object> variables, Map<String, Object> localVariables, EngineClientException e);

     void onFailure(String taskId, String errorMessage, String errorDetails, int retries, long retryTimeout);
     void failureDone(String taskId, String errorMessage, String errorDetails, int retries, long retryTimeout);
     void failureFail(String taskId, String errorMessage, String errorDetails, int retries, long retryTimeout, EngineClientException e);

     void onBpmnError(String taskId, String errorCode, String errorMessage, Map<String, Object> variables);
     void bpmnErrorDone(String taskId, String errorCode, String errorMessage, Map<String, Object> variables);
     void bpmnErrorFail(String taskId, String errorCode, String errorMessage, Map<String, Object> variables, EngineClientException e);

     void onExtendLock(String taskId, long newDuration);
     void extendLockDone(String taskId, long newDuration);
     void extendLockFail(String taskId, long newDuration, EngineClientException e);

}