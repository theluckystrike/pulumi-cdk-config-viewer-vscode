'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const {
  parseIacConfig,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryCsv,
  buildInventoryMarkdown,
} = require('../src/pulumiview');
const { IacViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

const SAMPLES = path.join(__dirname, '..', 'samples');

test('parses Pulumi stack YAML with secure and plaintext secret audit', () => {
  const buf = fs.readFileSync(path.join(SAMPLES, 'Pulumi.prod.yaml'));
  const parsed = parseIacConfig(buf, 'Pulumi.prod.yaml');
  assert.equal(parsed.meta.format, 'Pulumi Stack');
  assert.ok(parsed.rows.length >= 6);
  assert.ok(parsed.secrets.some((s) => s.status === 'encrypted' && s.key === 'app:stripeApiKey'));
  assert.ok(parsed.findings.some((f) => f.rule === 'PULUMI_PLAINTEXT_SECRET' && f.target === 'app:dbPassword'));
  assert.equal(parsed.stats.findingErrors, 1);
});

test('parses AWS CDK cdk.json feature flags and account/region context', () => {
  const buf = fs.readFileSync(path.join(SAMPLES, 'cdk.json'));
  const parsed = parseIacConfig(buf, 'cdk.json');
  assert.equal(parsed.meta.format, 'AWS CDK Config');
  assert.ok(parsed.flags.length >= 5);
  assert.ok(parsed.stacks.some((s) => s.kind === 'CDK Context Binding'));
  assert.ok(parsed.findings.some((f) => f.rule === 'CDK_SECURITY_FLAG_FALSE'));
});

test('parses synthesized CDK CloudFormation template IAM, SG and S3 findings', () => {
  const buf = fs.readFileSync(path.join(SAMPLES, 'app.template.json'));
  const parsed = parseIacConfig(buf, 'app.template.json');
  assert.equal(parsed.meta.format, 'CDK Template');
  assert.equal(parsed.stats.resourceCount, 3);
  assert.ok(parsed.findings.some((f) => f.rule === 'CFN_IAM_WILDCARD'));
  assert.ok(parsed.findings.some((f) => f.rule === 'CFN_OPEN_SG_INGRESS'));
  assert.ok(parsed.findings.some((f) => f.rule === 'CFN_S3_PUBLIC_OR_UNENCRYPTED'));
});

test('IacViewModel filters by kind, findings and search text', () => {
  const buf = fs.readFileSync(path.join(SAMPLES, 'Pulumi.prod.yaml'));
  const parsed = parseIacConfig(buf, 'Pulumi.prod.yaml');
  const vm = new IacViewModel(parsed, 'Pulumi.prod.yaml', buf.length);
  assert.equal(vm.setFilter({ kind: 'findings' }), 1);
  assert.equal(vm.setFilter({ kind: 'secret' }), 1);
  assert.ok(vm.setFilter({ text: 'us-east-1' }) >= 1);
  assert.ok(vm.detail(1).attrs.length >= 3);
});

test('Markdown audit, diff and CSV/MD inventory builders produce valid output', () => {
  const left = parseIacConfig(fs.readFileSync(path.join(SAMPLES, 'Pulumi.prod.yaml')), 'Pulumi.prod.yaml');
  const right = parseIacConfig(fs.readFileSync(path.join(SAMPLES, 'cdk.json')), 'cdk.json');
  const audit = buildAuditMarkdown([{ fileName: 'Pulumi.prod.yaml', parsed: left }]);
  assert.match(audit, /PULUMI_PLAINTEXT_SECRET/);
  const diff = buildDiffMarkdown('Pulumi.prod.yaml', left, 'cdk.json', right);
  assert.match(diff, /IaC Config Diff/);
  const csv = buildInventoryCsv(left);
  assert.match(csv, /^line,name,scope,kind,value,security,risk,errors,warnings/);
  const md = buildInventoryMarkdown(left, 'Pulumi.prod.yaml');
  assert.match(md, /IaC Inventory/);
});

test('editorHtml uses strict nonce CSP', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://x', script: 'v.js', styleUri: 'v.css', title: 'Pulumi.prod.yaml', nonce: 'abc123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-abc123'/);
  assert.ok(csp('vscode-webview://x', 'abc123').includes("default-src 'none'"));
});
