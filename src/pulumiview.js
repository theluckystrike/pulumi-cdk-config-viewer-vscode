'use strict';
// Offline zero-cloud parser and security analyzer for Pulumi YAML and AWS CDK JSON/template configs.

const SECRET_KEY_RE = /(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|auth|credential|dsn|jwt|signing|db[_-]?url|connection[_-]?string)/i;
const AWS_KEY_RE = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/;
const SENSITIVE_PORTS = new Set([22, 3389, 5432, 3306, 6379, 27017, 1433, 9200]);

function unquote(s) {
  const t = String(s || '').trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

function stripComment(line) {
  let inS = false;
  let inD = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    else if (ch === '#' && !inS && !inD && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function splitKeyVal(text) {
  let inS = false;
  let inD = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === "'" && !inD) inS = !inS;
    else if (ch === '"' && !inS) inD = !inD;
    else if (ch === ':' && !inS && !inD) {
      const next = text[i + 1];
      if (next === undefined || next === ' ' || next === '\t') {
        const key = unquote(text.slice(0, i).trim());
        const rest = text.slice(i + 1).trim();
        return { key, value: unquote(rest), rawValue: rest };
      }
    }
  }
  return null;
}

function csvCell(v) {
  const s = String(v == null ? '' : v).replace(/\r?\n/g, ' ');
  return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function mdCell(v) {
  return String(v == null ? '' : v).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function isPlaceholder(val) {
  const s = String(val || '').trim();
  if (!s) return true;
  if (/^\$\{[^}]+\}$/.test(s) || /^<[A-Z0-9_ -]+>$/.test(s)) return true;
  if (/^(changeme|example|placeholder|dummy|todo|redacted|xxx+|none|null|false|true)$/i.test(s)) return true;
  return false;
}

function findJsonKeyLine(lines, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"\\s*:`);
  for (let i = 0; i < lines.length; i += 1) {
    if (re.test(lines[i])) return i + 1;
  }
  return 1;
}

function parsePulumiYaml(text, fileName) {
  const lines = text.split(/\r?\n/);
  const lower = String(fileName || '').toLowerCase();
  const stackMatch = String(fileName || '').match(/^Pulumi\.([^.]+)\.ya?ml$/i);
  const isStack = Boolean(stackMatch) || /^\s*(encryptionsalt|secretsprovider)\s*:/m.test(text);
  const stackName = stackMatch ? stackMatch[1] : (isStack ? 'stack' : 'project');

  const rows = [];
  const stacks = [];
  const secrets = [];
  const flags = [];
  const findings = [];

  let projectName = '';
  let runtime = '';
  let backendUrl = '';
  let encryptionSalt = '';
  let secretsProvider = '';
  let topKey = '';
  let curConfigKey = null;
  let curConfigLine = 1;
  let curConfigRaw = [];

  const flushConfigEntry = () => {
    if (!curConfigKey) return;
    const raw = curConfigRaw.join('\n').trim();
    const isSecure = /\bsecure\s*:\s*\S+/.test(raw);
    const nsIdx = curConfigKey.indexOf(':');
    const namespace = nsIdx > 0 ? curConfigKey.slice(0, nsIdx) : stackName;
    const shortKey = nsIdx > 0 ? curConfigKey.slice(nsIdx + 1) : curConfigKey;
    const valMatch = raw.match(/:\s*(.+)$/);
    const scalarVal = isSecure ? '[encrypted ciphertext]' : unquote(valMatch ? valMatch[1] : '');
    const rowFindings = [];

    if (isSecure) {
      secrets.push({
        line: curConfigLine,
        key: curConfigKey,
        status: 'encrypted',
        provider: secretsProvider || (encryptionSalt ? 'pulumi-passphrase' : 'default'),
        detail: 'Protected with Pulumi secure ciphertext.',
        risk: 'ok',
      });
    } else if (SECRET_KEY_RE.test(shortKey) || AWS_KEY_RE.test(raw)) {
      const msg = `Config key "${curConfigKey}" looks like a secret but is stored in plaintext instead of a secure: ciphertext.`;
      const f = { severity: 'error', category: 'Secrets', rule: 'PULUMI_PLAINTEXT_SECRET', line: curConfigLine, target: curConfigKey, message: msg };
      findings.push(f);
      rowFindings.push(f);
      secrets.push({
        line: curConfigLine,
        key: curConfigKey,
        status: 'plaintext',
        provider: 'UNENCRYPTED',
        detail: msg,
        risk: 'error',
      });
    }

    rows.push({
      index: rows.length + 1,
      line: curConfigLine,
      name: curConfigKey,
      scope: namespace,
      kind: isSecure ? 'secret' : 'config',
      value: scalarVal || '(object/list)',
      security: isSecure ? 'secure (encrypted)' : (rowFindings.length ? 'plaintext secret' : 'plaintext'),
      badge: isSecure ? 'secure' : 'config',
      risk: rowFindings.some((x) => x.severity === 'error') ? 'error' : (rowFindings.length ? 'review' : 'ok'),
      errorCount: rowFindings.filter((x) => x.severity === 'error').length,
      warningCount: rowFindings.filter((x) => x.severity === 'warning').length,
      findings: rowFindings,
      raw,
      attrs: [
        { key: 'Config Key', value: curConfigKey },
        { key: 'Namespace', value: namespace },
        { key: 'Encryption', value: isSecure ? 'secure: ciphertext' : 'plaintext' },
        { key: 'Value Preview', value: isSecure ? '[encrypted]' : (scalarVal || '(structured value)') },
      ],
    });
    curConfigKey = null;
    curConfigRaw = [];
  };

  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i];
    const clean = stripComment(rawLine);
    if (!clean.trim()) continue;
    const indent = clean.match(/^(\s*)/)[1].length;
    const trimmed = clean.trim();
    const lineNo = i + 1;

    if (indent === 0) {
      flushConfigEntry();
      const kv = splitKeyVal(trimmed);
      if (!kv) continue;
      topKey = kv.key;
      if (kv.key === 'name') projectName = kv.value;
      else if (kv.key === 'runtime' && kv.value) runtime = kv.value;
      else if (kv.key === 'encryptionsalt') encryptionSalt = kv.value;
      else if (kv.key === 'secretsprovider') secretsProvider = kv.value;
      else if (kv.key === 'backend' && kv.value) backendUrl = kv.value;
      continue;
    }

    if (topKey === 'runtime' && indent >= 2) {
      const kv = splitKeyVal(trimmed);
      if (kv && kv.key === 'name' && kv.value) runtime = kv.value;
    } else if (topKey === 'backend' && indent >= 2) {
      const kv = splitKeyVal(trimmed);
      if (kv && kv.key === 'url' && kv.value) backendUrl = kv.value;
    } else if (topKey === 'config') {
      if (indent === 2 && !trimmed.startsWith('-')) {
        flushConfigEntry();
        const kv = splitKeyVal(trimmed);
        if (kv) {
          curConfigKey = kv.key;
          curConfigLine = lineNo;
          curConfigRaw = [rawLine];
        }
      } else if (curConfigKey) {
        curConfigRaw.push(rawLine);
      }
    } else if ((topKey === 'outputs' || topKey === 'resources') && indent === 2 && !trimmed.startsWith('-')) {
      const kv = splitKeyVal(trimmed);
      if (kv) {
        const isOut = topKey === 'outputs';
        if (isOut) {
          flags.push({ line: lineNo, name: kv.key, value: kv.value || '(expr)', category: 'Pulumi Output', status: 'ok' });
        }
        rows.push({
          index: rows.length + 1,
          line: lineNo,
          name: kv.key,
          scope: isOut ? 'outputs' : 'resources',
          kind: isOut ? 'output' : 'resource',
          value: kv.value || '(block)',
          security: 'declarative',
          badge: isOut ? 'output' : 'resource',
          risk: 'ok',
          errorCount: 0,
          warningCount: 0,
          findings: [],
          raw: rawLine.trim(),
          attrs: [
            { key: 'Section', value: topKey },
            { key: 'Name', value: kv.key },
            { key: 'Value', value: kv.value || '(nested block)' },
          ],
        });
      }
    }
  }
  flushConfigEntry();

  if (isStack) {
    if (!encryptionSalt && !secretsProvider && rows.length > 0) {
      findings.push({
        severity: 'warning',
        category: 'Encryption',
        rule: 'PULUMI_NO_ENCRYPTION_SALT',
        line: 1,
        target: stackName,
        message: 'Stack config has no encryptionsalt or secretsprovider configured.',
      });
    }
    stacks.push({
      line: 1,
      name: stackName,
      kind: 'Pulumi Stack',
      binding: secretsProvider || (encryptionSalt ? 'passphrase-salt' : 'none'),
      detail: `${rows.length} config keys, ${secrets.filter((s) => s.status === 'encrypted').length} encrypted secrets`,
    });
  } else {
    if (backendUrl && backendUrl.startsWith('file://')) {
      findings.push({
        severity: 'warning',
        category: 'State',
        rule: 'PULUMI_LOCAL_BACKEND',
        line: findJsonKeyLine(lines, 'backend'),
        target: backendUrl,
        message: 'Pulumi project uses a local file:// backend URL; team deployments typically use remote state.',
      });
    }
    stacks.push({
      line: 1,
      name: projectName || lower,
      kind: 'Pulumi Project',
      binding: runtime || 'unspecified',
      detail: backendUrl ? `backend: ${backendUrl}` : 'default Pulumi backend',
    });
    if (rows.length === 0) {
      rows.push({
        index: 1,
        line: 1,
        name: projectName || fileName,
        scope: 'project',
        kind: 'stack',
        value: runtime || 'unspecified',
        security: backendUrl && backendUrl.startsWith('file://') ? 'local backend' : 'standard',
        badge: 'project',
        risk: backendUrl && backendUrl.startsWith('file://') ? 'review' : 'ok',
        errorCount: 0,
        warningCount: backendUrl && backendUrl.startsWith('file://') ? 1 : 0,
        findings: findings.slice(),
        raw: text.slice(0, 800),
        attrs: [
          { key: 'Project', value: projectName || '(unnamed)' },
          { key: 'Runtime', value: runtime || '(unspecified)' },
          { key: 'Backend', value: backendUrl || '(default)' },
        ],
      });
    }
  }

  return buildResult({
    format: isStack ? 'Pulumi Stack' : 'Pulumi Project',
    fileName,
    totalLines: lines.length,
    rows,
    stacks,
    secrets,
    flags,
    findings,
  });
}

function parseCdkJson(text, fileName) {
  const lines = text.split(/\r?\n/);
  let data;
  try {
    data = JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON in ${fileName}: ${e.message}`);
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error(`${fileName} must contain a top-level JSON object.`);
  }

  const rows = [];
  const stacks = [];
  const secrets = [];
  const flags = [];
  const findings = [];

  const isCfnTemplate = Boolean(data.Resources && typeof data.Resources === 'object');
  const isContextOnly = /cdk\.context\.json$/i.test(fileName) && !data.app && !isCfnTemplate;

  if (isCfnTemplate) {
    const resources = data.Resources || {};
    for (const [logicalId, res] of Object.entries(resources)) {
      const rType = (res && res.Type) || 'Unknown';
      const props = (res && res.Properties) || {};
      const lineNo = findJsonKeyLine(lines, logicalId);
      const raw = JSON.stringify(res, null, 2);
      const rowFindings = [];

      if (AWS_KEY_RE.test(raw)) {
        const f = { severity: 'error', category: 'Secrets', rule: 'CDK_HARDCODED_SECRET', line: lineNo, target: logicalId, message: `Hardcoded AWS access key pattern found inside resource "${logicalId}".` };
        findings.push(f);
        rowFindings.push(f);
        secrets.push({ line: lineNo, key: logicalId, status: 'hardcoded', provider: rType, detail: f.message, risk: 'error' });
      }

      if (rType === 'AWS::IAM::Role' || rType === 'AWS::IAM::Policy' || rType === 'AWS::IAM::ManagedPolicy') {
        const docs = [];
        if (props.PolicyDocument) docs.push(props.PolicyDocument);
        if (Array.isArray(props.Policies)) {
          for (const p of props.Policies) if (p && p.PolicyDocument) docs.push(p.PolicyDocument);
        }
        for (const doc of docs) {
          const stmts = Array.isArray(doc.Statement) ? doc.Statement : (doc.Statement ? [doc.Statement] : []);
          for (const st of stmts) {
            if (!st || String(st.Effect || 'Allow').toLowerCase() !== 'allow') continue;
            const actions = Array.isArray(st.Action) ? st.Action : [st.Action];
            const resList = Array.isArray(st.Resource) ? st.Resource : [st.Resource];
            if (actions.includes('*') || resList.includes('*')) {
              const f = {
                severity: 'error',
                category: 'IAM',
                rule: 'CFN_IAM_WILDCARD',
                line: lineNo,
                target: logicalId,
                message: `IAM resource "${logicalId}" allows wildcard Action (${actions.join(',')}) or Resource (${resList.join(',')}).`,
              };
              findings.push(f);
              rowFindings.push(f);
              secrets.push({ line: lineNo, key: logicalId, status: 'wildcard-iam', provider: rType, detail: f.message, risk: 'error' });
            }
          }
        }
      }

      if (rType === 'AWS::EC2::SecurityGroup' && Array.isArray(props.SecurityGroupIngress)) {
        for (const rule of props.SecurityGroupIngress) {
          const cidr = String(rule.CidrIp || rule.CidrIpv6 || '');
          const fromP = Number(rule.FromPort);
          const toP = Number(rule.ToPort);
          const openWorld = cidr === '0.0.0.0/0' || cidr === '::/0';
          const riskyPort = rule.IpProtocol === '-1' || SENSITIVE_PORTS.has(fromP) || SENSITIVE_PORTS.has(toP);
          if (openWorld && riskyPort) {
            const f = {
              severity: 'error',
              category: 'Network',
              rule: 'CFN_OPEN_SG_INGRESS',
              line: lineNo,
              target: logicalId,
              message: `SecurityGroup "${logicalId}" exposes port ${fromP || 'all'} to ${cidr}.`,
            };
            findings.push(f);
            rowFindings.push(f);
            secrets.push({ line: lineNo, key: logicalId, status: 'open-ingress', provider: rType, detail: f.message, risk: 'error' });
          }
        }
      }

      if (rType === 'AWS::S3::Bucket') {
        const acl = String(props.AccessControl || '');
        if (/public/i.test(acl) || !props.BucketEncryption || !props.PublicAccessBlockConfiguration) {
          const f = {
            severity: 'warning',
            category: 'Storage',
            rule: 'CFN_S3_PUBLIC_OR_UNENCRYPTED',
            line: lineNo,
            target: logicalId,
            message: `S3 bucket "${logicalId}" is missing BucketEncryption or PublicAccessBlockConfiguration (or uses public ACL).`,
          };
          findings.push(f);
          rowFindings.push(f);
        }
      }

      if (rType === 'AWS::RDS::DBInstance') {
        if (props.PubliclyAccessible === true || props.StorageEncrypted === false) {
          const f = {
            severity: 'warning',
            category: 'Database',
            rule: 'CFN_RDS_PUBLIC_OR_UNENCRYPTED',
            line: lineNo,
            target: logicalId,
            message: `RDS instance "${logicalId}" has PubliclyAccessible=true or StorageEncrypted=false.`,
          };
          findings.push(f);
          rowFindings.push(f);
        }
      }

      rows.push({
        index: rows.length + 1,
        line: lineNo,
        name: logicalId,
        scope: rType,
        kind: 'resource',
        value: Object.keys(props).slice(0, 4).join(', ') || '(no properties)',
        security: rowFindings.length ? `${rowFindings.length} finding(s)` : 'ok',
        badge: rType.split('::')[1] || 'AWS',
        risk: rowFindings.some((x) => x.severity === 'error') ? 'error' : (rowFindings.length ? 'review' : 'ok'),
        errorCount: rowFindings.filter((x) => x.severity === 'error').length,
        warningCount: rowFindings.filter((x) => x.severity === 'warning').length,
        findings: rowFindings,
        raw,
        attrs: [
          { key: 'Logical ID', value: logicalId },
          { key: 'Resource Type', value: rType },
          { key: 'Properties', value: Object.keys(props).join(', ') || '(none)' },
        ],
      });
    }

    for (const [outKey, outObj] of Object.entries(data.Outputs || {})) {
      const lineNo = findJsonKeyLine(lines, outKey);
      flags.push({
        line: lineNo,
        name: outKey,
        value: typeof outObj.Value === 'string' ? outObj.Value : JSON.stringify(outObj.Value),
        category: 'CFN Output',
        status: 'ok',
      });
    }
    for (const [pKey, pObj] of Object.entries(data.Parameters || {})) {
      const lineNo = findJsonKeyLine(lines, pKey);
      flags.push({
        line: lineNo,
        name: pKey,
        value: `${pObj.Type || 'String'}${pObj.Default !== undefined ? ` = ${pObj.Default}` : ''}`,
        category: 'CFN Parameter',
        status: 'ok',
      });
    }
    stacks.push({
      line: 1,
      name: fileName,
      kind: 'CDK CloudFormation Template',
      binding: data.AWSTemplateFormatVersion || '2010-09-09',
      detail: `${Object.keys(resources).length} resources, ${Object.keys(data.Outputs || {}).length} outputs`,
    });

    return buildResult({
      format: 'CDK Template',
      fileName,
      totalLines: lines.length,
      rows,
      stacks,
      secrets,
      flags,
      findings,
    });
  }

  // cdk.json or cdk.context.json
  const ctx = isContextOnly ? data : (data.context && typeof data.context === 'object' ? data.context : {});
  if (!isContextOnly && data.app) {
    const lineNo = findJsonKeyLine(lines, 'app');
    stacks.push({
      line: lineNo,
      name: 'CDK App Entry',
      kind: 'AWS CDK Config',
      binding: String(data.app),
      detail: data.output ? `output: ${data.output}` : 'output: cdk.out',
    });
  }

  for (const [k, v] of Object.entries(ctx)) {
    const lineNo = findJsonKeyLine(lines, k);
    const valStr = typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v);
    const isFlag = k.startsWith('@aws-cdk/');
    const isEnvBind = /^(availability-zones|vpc-provider|hosted-zone|ami|ssm|security-group):/.test(k);
    const rowFindings = [];

    if (isFlag) {
      const securityFlag = /(minimizePolicies|denyAnonymousAccess|createDefaultLoggingPolicy|restrictDefaultSecurityGroup|useDefaultAccessLogs)/i.test(k);
      const disabledSecurity = securityFlag && v === false;
      if (disabledSecurity) {
        const f = {
          severity: 'warning',
          category: 'Feature Flags',
          rule: 'CDK_SECURITY_FLAG_FALSE',
          line: lineNo,
          target: k,
          message: `Security-relevant CDK feature flag "${k}" is set to false.`,
        };
        findings.push(f);
        rowFindings.push(f);
      }
      flags.push({
        line: lineNo,
        name: k,
        value: valStr,
        category: 'CDK Feature Flag',
        status: disabledSecurity ? 'review' : 'ok',
      });
    } else if (isEnvBind) {
      const acctMatch = k.match(/account=(\d{12})/);
      const regMatch = k.match(/region=([a-z0-9-]+)/);
      stacks.push({
        line: lineNo,
        name: k.split(':')[0],
        kind: 'CDK Context Binding',
        binding: `${acctMatch ? acctMatch[1] : 'default'} / ${regMatch ? regMatch[1] : 'default'}`,
        detail: valStr.slice(0, 120),
      });
    }

    if ((SECRET_KEY_RE.test(k) && !isPlaceholder(valStr)) || AWS_KEY_RE.test(valStr)) {
      const f = {
        severity: 'error',
        category: 'Secrets',
        rule: 'CDK_HARDCODED_SECRET',
        line: lineNo,
        target: k,
        message: `CDK context key "${k}" appears to contain a hardcoded secret value.`,
      };
      findings.push(f);
      rowFindings.push(f);
      secrets.push({ line: lineNo, key: k, status: 'plaintext', provider: 'cdk-context', detail: f.message, risk: 'error' });
    }

    rows.push({
      index: rows.length + 1,
      line: lineNo,
      name: k,
      scope: isFlag ? '@aws-cdk' : (isEnvBind ? k.split(':')[0] : 'context'),
      kind: isFlag ? 'flag' : (isEnvBind ? 'stack' : 'config'),
      value: valStr.slice(0, 120),
      security: rowFindings.length ? 'review' : 'ok',
      badge: isFlag ? 'flag' : (isEnvBind ? 'context' : 'config'),
      risk: rowFindings.some((x) => x.severity === 'error') ? 'error' : (rowFindings.length ? 'review' : 'ok'),
      errorCount: rowFindings.filter((x) => x.severity === 'error').length,
      warningCount: rowFindings.filter((x) => x.severity === 'warning').length,
      findings: rowFindings,
      raw: `"${k}": ${JSON.stringify(v, null, 2)}`,
      attrs: [
        { key: 'Key', value: k },
        { key: 'Kind', value: isFlag ? 'CDK Feature Flag' : (isEnvBind ? 'Account/Region Context' : 'Context Value') },
        { key: 'Value', value: valStr.slice(0, 240) },
      ],
    });
  }

  return buildResult({
    format: isContextOnly ? 'AWS CDK Context' : 'AWS CDK Config',
    fileName,
    totalLines: lines.length,
    rows,
    stacks,
    secrets,
    flags,
    findings,
  });
}

function buildResult({ format, fileName, totalLines, rows, stacks, secrets, flags, findings }) {
  const findingErrors = findings.filter((f) => f.severity === 'error').length;
  const findingWarnings = findings.filter((f) => f.severity === 'warning').length;
  return {
    meta: { format, fileName },
    totalLines,
    rows,
    stacks,
    secrets,
    flags,
    findings,
    stats: {
      rowCount: rows.length,
      stackCount: stacks.length,
      secretCount: secrets.length,
      flagCount: flags.length,
      resourceCount: rows.filter((r) => r.kind === 'resource').length,
      findingErrors,
      findingWarnings,
    },
  };
}

function parseIacConfig(bufOrStr, fileName = 'Pulumi.yaml') {
  const text = Buffer.isBuffer(bufOrStr) ? bufOrStr.toString('utf8') : String(bufOrStr || '');
  if (!text.trim()) throw new Error(`${fileName} is empty.`);
  const trimmed = text.trim();
  if (/\.json$/i.test(fileName) || trimmed.startsWith('{')) {
    return parseCdkJson(text, fileName);
  }
  return parsePulumiYaml(text, fileName);
}

function buildAuditMarkdown(entries) {
  const lines = ['# Pulumi & AWS CDK Security Audit', ''];
  for (const { fileName, parsed } of entries) {
    const s = parsed.stats;
    lines.push(`## ${fileName} (${parsed.meta.format})`);
    lines.push('');
    lines.push(`- Items: ${s.rowCount} | Stacks/Context: ${s.stackCount} | Secrets/IAM: ${s.secretCount} | Flags/Outputs: ${s.flagCount}`);
    lines.push(`- Findings: ${s.findingErrors} error(s), ${s.findingWarnings} warning(s)`);
    lines.push('');
    if (parsed.findings.length) {
      lines.push('| Severity | Category | Rule | Line | Target | Message |');
      lines.push('| --- | --- | --- | ---: | --- | --- |');
      for (const f of parsed.findings) {
        lines.push(`| ${mdCell(f.severity.toUpperCase())} | ${mdCell(f.category)} | \`${mdCell(f.rule)}\` | ${f.line} | \`${mdCell(f.target)}\` | ${mdCell(f.message)} |`);
      }
    } else {
      lines.push('No security or configuration findings.');
    }
    lines.push('');
  }
  return lines.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const lMap = new Map(left.rows.map((r) => [r.name, r]));
  const rMap = new Map(right.rows.map((r) => [r.name, r]));
  const added = [];
  const removed = [];
  const changed = [];

  for (const [k, rv] of rMap.entries()) {
    if (!lMap.has(k)) added.push(rv);
    else {
      const lv = lMap.get(k);
      if (lv.value !== rv.value || lv.security !== rv.security || lv.risk !== rv.risk) {
        changed.push({ name: k, left: lv, right: rv });
      }
    }
  }
  for (const [k, lv] of lMap.entries()) {
    if (!rMap.has(k)) removed.push(lv);
  }

  const lines = [
    `# IaC Config Diff: ${leftName} vs ${rightName}`,
    '',
    `- Added: ${added.length} | Removed: ${removed.length} | Changed: ${changed.length}`,
    '',
  ];
  if (added.length) {
    lines.push('## Added', '', '| Key / Resource | Kind | Value | Security |', '| --- | --- | --- | --- |');
    for (const r of added) lines.push(`| \`${mdCell(r.name)}\` | ${mdCell(r.kind)} | ${mdCell(r.value)} | ${mdCell(r.security)} |`);
    lines.push('');
  }
  if (removed.length) {
    lines.push('## Removed', '', '| Key / Resource | Kind | Value | Security |', '| --- | --- | --- | --- |');
    for (const r of removed) lines.push(`| \`${mdCell(r.name)}\` | ${mdCell(r.kind)} | ${mdCell(r.value)} | ${mdCell(r.security)} |`);
    lines.push('');
  }
  if (changed.length) {
    lines.push('## Changed', '', '| Key / Resource | Before | After |', '| --- | --- | --- |');
    for (const c of changed) lines.push(`| \`${mdCell(c.name)}\` | ${mdCell(c.left.value)} (${mdCell(c.left.security)}) | ${mdCell(c.right.value)} (${mdCell(c.right.security)}) |`);
    lines.push('');
  }
  if (!added.length && !removed.length && !changed.length) {
    lines.push('No differences found between parsed items.');
  }
  return lines.join('\n');
}

function buildInventoryCsv(parsed) {
  const header = ['line', 'name', 'scope', 'kind', 'value', 'security', 'risk', 'errors', 'warnings'];
  const out = [header.join(',')];
  for (const r of parsed.rows) {
    out.push([r.line, r.name, r.scope, r.kind, r.value, r.security, r.risk, r.errorCount, r.warningCount].map(csvCell).join(','));
  }
  return out.join('\n') + '\n';
}

function buildInventoryMarkdown(parsed, fileName) {
  const lines = [
    `# IaC Inventory: ${fileName} (${parsed.meta.format})`,
    '',
    '| Line | Key / Resource | Scope / Type | Kind | Security | Status |',
    '| ---: | --- | --- | --- | --- | --- |',
  ];
  for (const r of parsed.rows) {
    lines.push(`| ${r.line} | \`${mdCell(r.name)}\` | \`${mdCell(r.scope)}\` | ${mdCell(r.kind)} | ${mdCell(r.security)} | ${mdCell(r.risk)} |`);
  }
  return lines.join('\n') + '\n';
}

module.exports = {
  parseIacConfig,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildInventoryCsv,
  buildInventoryMarkdown,
};
