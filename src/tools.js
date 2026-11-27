'use strict';
// Pro tools for Pulumi & AWS CDK Config Viewer:
//   1. auditIacConfig: Offline Markdown secrets, IAM, security group and feature-flag audit.
//   2. diffIacConfigs: Compare two Pulumi or AWS CDK configs in Markdown.
//   3. exportIacInventory: Non-destructive Markdown and CSV config and resource inventory export.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parseIacConfig,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryCsv,
  buildInventoryMarkdown,
} = require('./pulumiview');

const MATCH_RE = /^(Pulumi(\.[^.]+)?\.ya?ml|cdk(\.context)?\.json|.+\.template\.json)$/i;

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Pulumi YAML, cdk.json or CDK template file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && MATCH_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    filters: { 'Pulumi & CDK Configs': ['yaml', 'yml', 'json'] },
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listIacConfigsInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist' || e.name === 'build') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && MATCH_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditIacConfig(uri, opts = {}) {
    if (!(await pro.allowed('auditIacConfig', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listIacConfigsInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No Pulumi YAML, cdk.json or CDK template files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      const label = isDir ? path.relative(targetPath, f) : path.basename(f);
      entries.push({ fileName: label, parsed: parseIacConfig(buf, path.basename(f)) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditIacConfig');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffIacConfigs(uri, opts = {}) {
    if (!(await pro.allowed('diffIacConfigs', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Pulumi or CDK config');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        filters: { 'Pulumi & CDK Configs': ['yaml', 'yml', 'json'] },
        openLabel: 'Select second Pulumi or CDK config to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildDiffMarkdown(
      leftName,
      parseIacConfig(leftBuf, leftName),
      rightName,
      parseIacConfig(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffIacConfigs');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportIacInventory(uri, opts = {}) {
    if (!(await pro.allowed('exportIacInventory', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parseIacConfig(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/[^a-zA-Z0-9._-]+/g, '_') || 'iac-config';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.inventory.csv`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'CSV IaC Inventory': ['csv'] },
        saveLabel: 'Save Markdown and CSV IaC inventory',
      });
    if (!saveUri) return undefined;

    const csvPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(csvPath);
    const stem = path.basename(csvPath, '.csv').replace(/\.inventory$/i, '');
    const mdPath = uniquePath(path.join(dir, `${stem}.inventory.md`));

    fs.writeFileSync(csvPath, buildInventoryCsv(parsed), 'utf8');
    fs.writeFileSync(mdPath, buildInventoryMarkdown(parsed, baseName), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportIacInventory');
    if (reach) reach.refresh();
    return { files: [csvPath, mdPath], items: parsed.rows.length };
  }

  return { auditIacConfig, diffIacConfigs, exportIacInventory };
}

module.exports = { createTools, uniquePath, listIacConfigsInDir };
