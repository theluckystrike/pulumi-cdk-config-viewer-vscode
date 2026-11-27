'use strict';
module.exports = {
  prefix: 'zovoPulumiview',
  triesKey: 'zovoPulumiview.proTrial',
  slot: '#protools',
  tools: [
    { id: 'auditIacConfig', title: 'Audit Pulumi & CDK config security', command: 'zovoPulumiview.auditIacConfig' },
    { id: 'diffIacConfigs', title: 'Compare two Pulumi or CDK configs', command: 'zovoPulumiview.diffIacConfigs' },
    { id: 'exportIacInventory', title: 'Export IaC resource & config inventory', command: 'zovoPulumiview.exportIacInventory' },
  ],
};
