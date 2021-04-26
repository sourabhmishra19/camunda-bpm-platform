<#-- Generated From File: camunda-docs-manual/public/reference/rest/migration/execute-migration/index.html -->
<#macro dto_macro docsUrl="">
<@lib.dto>
    
    <@lib.property
        name = "migrationPlan"
        type = "object"
        dto = "MigrationPlanDto"
        additionalProperties = true
        desc = "The migration plan to execute. A JSON object corresponding to
                the migration plan interface in the engine as explained below."
    />

    
    <@lib.property
        name = "processInstanceIds"
        type = "array"
        desc = "A list of process instance ids to migrate."
    />

    
    <@lib.property
        name = "processInstanceQuery"
        type = "object"
        dto = "ProcessInstanceQueryDto"
        desc = "A process instance query like the request body described by
                [POST /process-instance](${docsUrl}/reference/rest/process-instance/post-query/#request-body)."
    />

    
    <@lib.property
        name = "skipCustomListeners"
        type = "boolean"
        desc = "A boolean value to control whether execution listeners should be invoked during
                migration."
    />

    
    <@lib.property
        name = "skipIoMappings"
        type = "boolean"
        desc = "A boolean value to control whether input/output mappings should be executed during
                migration."
        last = true
    />


</@lib.dto>
</#macro>