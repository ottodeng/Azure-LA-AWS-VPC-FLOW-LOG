targetScope = 'resourceGroup'

@description('Azure region for the MCP service.')
param location string = resourceGroup().location

@description('Container App name.')
param containerAppName string = 'aws-vpc-flow-mcp'

@description('OCI image containing this MCP server.')
param image string

@description('Customer ID GUID of the Log Analytics workspace containing AWSVPCFlow.')
param awsVpcFlowWorkspaceId string

@description('Microsoft Entra tenant ID.')
param tenantId string

@description('MCP API application ID URI or audience.')
param mcpAudience string

@description('Delegated OAuth scope required by the MCP server.')
param mcpScope string = 'aws_vpc_flow.read'

@description('Serialized access-policy JSON with Entra group or App Role mappings.')
param accessPolicyJson string

@description('OpenClaw HTTPS origin allowed by MCP transport security.')
param openClawOrigin string = ''

@description('Expose the Container App through external HTTPS ingress.')
param externalIngress bool = false

@minValue(1)
param minReplicas int = 1

@minValue(1)
param maxReplicas int = 3

var environmentName = '${containerAppName}-env'
var monitoringWorkspaceName = '${containerAppName}-monitor'

resource monitoringWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: monitoringWorkspaceName
  location: location
  properties: {
    retentionInDays: 30
    sku: {
      name: 'PerGB2018'
    }
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: monitoringWorkspace.properties.customerId
        sharedKey: monitoringWorkspace.listKeys().primarySharedKey
      }
    }
  }
}

var mcpHost = '${containerAppName}.${environment.properties.defaultDomain}'
var mcpUrl = 'https://${mcpHost}/mcp'

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: containerAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: externalIngress
        allowInsecure: false
        targetPort: 8000
        transport: 'http'
        traffic: [
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
    }
    template: {
      containers: [
        {
          name: 'mcp'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'AWS_VPC_FLOW_WORKSPACE_ID'
              value: awsVpcFlowWorkspaceId
            }
            {
              name: 'AWS_VPC_FLOW_AZURE_AUTH_MODE'
              value: 'managed-identity'
            }
            {
              name: 'AWS_VPC_FLOW_MCP_AUTH_MODE'
              value: 'entra'
            }
            {
              name: 'AWS_VPC_FLOW_MCP_TENANT_ID'
              value: tenantId
            }
            {
              name: 'AWS_VPC_FLOW_MCP_AUDIENCE'
              value: mcpAudience
            }
            {
              name: 'AWS_VPC_FLOW_MCP_SCOPE'
              value: mcpScope
            }
            {
              name: 'AWS_VPC_FLOW_MCP_SERVER_URL'
              value: mcpUrl
            }
            {
              name: 'AWS_VPC_FLOW_ALLOWED_HOSTS'
              value: mcpHost
            }
            {
              name: 'AWS_VPC_FLOW_ALLOWED_ORIGINS'
              value: openClawOrigin
            }
            {
              name: 'AWS_VPC_FLOW_ACCESS_POLICY_JSON'
              value: accessPolicyJson
            }
            {
              name: 'AWS_VPC_FLOW_LOG_LEVEL'
              value: 'INFO'
            }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/healthz'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/healthz'
                port: 8000
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
}

output mcpUrl string = mcpUrl
output managedIdentityPrincipalId string = app.identity.principalId
output monitoringWorkspaceResourceId string = monitoringWorkspace.id
