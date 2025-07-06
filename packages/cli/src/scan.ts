import fs from 'fs/promises';
import path from 'path';
import { GeminiChat } from '@whisper-ai/whisper-cli-core';
import { createContentGeneratorConfig, createContentGenerator, AuthType } from '@whisper-ai/whisper-cli-core';
import { exec } from 'child_process';

const MAX_BATCH_SIZE = 10000; // characters per Gemini prompt
const SUPPORTED_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs'];

async function collectFiles(dir: string, recursive: boolean, exclude: string[] = []): Promise<string[]> {
  let files: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (exclude.some((ex) => fullPath.includes(ex))) continue;
    if (entry.isDirectory()) {
      if (recursive) {
        files = files.concat(await collectFiles(fullPath, recursive, exclude));
      }
    } else if (SUPPORTED_EXTENSIONS.includes(path.extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

function parseGeminiResponse(text: string) {
  // Simple parser: look for lines like "[severity] description (file:line)"
  // For now, just return the text as a single finding
  return [{
    severity: 'unknown',
    description: text,
    file: '',
    line: 0,
    suggestion: ''
  }];
}

function toSarif(findings: any[], toolName = 'Whisper Security CLI') {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            informationUri: 'https://github.com/whisper-ai/whisper-cli',
            rules: [],
          },
        },
        results: findings.map(f => ({
          ruleId: f.severity,
          message: { text: f.description },
          locations: f.file ? [{
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: f.line ? { startLine: f.line } : undefined,
            },
          }] : [],
          properties: { suggestion: f.suggestion },
        })),
      },
    ],
  };
}

export async function scanCommand({ target = '.', recursive = false, language, exclude = '', format = 'pretty', output = '', engine = 'auto' }: { target?: string; recursive?: boolean; language?: string; exclude?: string; format?: string; output?: string; engine?: string }) {
  // 1. Collect code from the target
  let fileList: string[] = [];
  const stat = await fs.stat(target);
  if (stat.isDirectory()) {
    fileList = await collectFiles(target, recursive, exclude ? exclude.split(',') : []);
  } else {
    fileList = [target];
  }

  // Engine selection logic
  if (engine === 'local' || (engine === 'auto' && !process.env.WHISPER_API_KEY)) {
    // Use Semgrep as local engine (MVP)
    console.log('Running local static analysis (Semgrep)...');
    await runSemgrep(fileList, format, output);
    return;
  }

  // If engine is 'cloud' or 'auto' with API key, use backend (stub for now)
  if (engine === 'cloud' || engine === 'auto') {
    if (!process.env.WHISPER_API_KEY) {
      console.error('No API key found for cloud engine. Falling back to local engine.');
      await runSemgrep(fileList, format, output);
      return;
    }
    // TODO: Implement backend call
    console.log('Calling Whisper backend for AI-powered scan (stub)...');
    // Example: await callBackendScanAPI(fileList, ...)
    return;
  }
}

async function runSemgrep(fileList: string[], format: string, output: string) {
  // For MVP, just run semgrep on the files and print output
  const filesArg = fileList.map(f => `"${f}"`).join(' ');
  const cmd = `semgrep --config=auto ${filesArg} --json`;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error('Semgrep error:', stderr || error.message);
      return;
    }
    if (format === 'json' || format === 'pretty') {
      if (output) {
        fs.writeFile(output, stdout, 'utf8');
        console.log(`Results written to ${output}`);
      } else {
        console.log(stdout);
      }
    } else {
      // TODO: Convert to SARIF if needed
      console.log(stdout);
    }
  });
} 