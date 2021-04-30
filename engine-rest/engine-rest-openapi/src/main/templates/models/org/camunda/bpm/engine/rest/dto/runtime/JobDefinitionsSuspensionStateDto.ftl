<#-- Generated From File: camunda-docs-manual/public/reference/rest/job-definition/put-activate-suspend-by-id/index.html -->
<#macro dto_macro docsUrl="">

<#assign noteProcessDefinitionKey = "Note that this parameter will only be considered 
                                     in combination with `processDefinitionKey`." >

<@lib.dto extends="JobDefinitionSuspensionStateDto"
          desc = "Defines by which selection criterion to activate or suspend job definitions.
                  The selection criteria are mutually exclusive and can only be one of:
                  * `processDefinitionId`
                  * `processDefinitionKey`">
    
    <@lib.property
        name = "processDefinitionId"
        type = "string"
        desc = "The process definition id of the job definitions to activate or suspend."
    />
    
    <@lib.property
        name = "processDefinitionKey"
        type = "string"
        desc = "The process definition key of the job definitions to activate or suspend."
    />

    
    <@lib.property
        name = "processDefinitionTenantId"
        type = "string"
        desc = "Only activate or suspend job definitions of a process definition which belongs to a
                tenant with the given id.
                
                ${noteProcessDefinitionKey}"
    />

    
    <@lib.property
        name = "processDefinitionWithoutTenantId"
        type = "string"
        desc = "Only activate or suspend job definitions of a process definition which belongs to
                no tenant. Value may only be `true`, as `false` is the default
                behavior.
                
                ${noteProcessDefinitionKey}"
        last = true
    />

</@lib.dto>
</#macro>