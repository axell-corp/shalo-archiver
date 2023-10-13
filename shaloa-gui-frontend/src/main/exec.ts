import * as child_process from "child_process";
import * as path from "path";
import * as fs from "fs";
import { is } from "@electron-toolkit/utils";
import { app } from "electron";

const __SHALO_BIN_DIR__ = path.dirname(app.getPath("exe"));
const __SHALO_BIN_BUNDLED__ = !is.dev;

// test用
if (is.dev) {
  process.env.PORTABLE_EXECUTABLE_DIR = "../x64/Debug/";
}

export const execFileAsync = (filepath: string, args: string[] | null) =>
  new Promise<{
    err: Error | null;
    stdout: string;
    stderr: string;
  }>((resolve) =>
    child_process.execFile(filepath, args, (err, stdout, stderr) =>
      resolve({ err, stdout, stderr })
    )
  );

const execAsync = (
  filepath: string,
  args: string[] | null,
  stdinArg: string | null
) =>
  new Promise<{
    err: Error | null;
    stdout: string;
    stderr: string;
  }>((resolve) => {
    const p = child_process.execFile(filepath, args, (err, stdout, stderr) =>
      resolve({ err, stdout, stderr })
    );
    p.stdin?.write(stdinArg + "\n\n");
    p.stdin?.end();
  });

export const getExecPath = (filename: string) => {
  switch (process.platform) {
    case "win32": {
      if (__SHALO_BIN_BUNDLED__) {
        return path.join(__SHALO_BIN_DIR__, filename + ".exe");
      } else {
        const appPath = process.env.PORTABLE_EXECUTABLE_DIR ?? "./";
        return path.join(appPath, filename + ".exe");
      }
    }

    case "darwin":
    case "linux":
      return path.join(__dirname, __SHALO_BIN_DIR__, filename);

    default:
      throw `unsupported platform: ${process.platform}`;
  }
};

const setExecutablePermission = async (filepath: string) => {
  try {
    await fs.promises.access(filepath, fs.constants.X_OK);
  } catch (_) {
    try {
      await fs.promises.chmod(filepath, 0o755);
    } catch (_) {
      //ignore
    }
  }
  //double check
  try {
    await fs.promises.access(filepath, fs.constants.X_OK);
  } catch (_) {
    //ignore
  }
};

export const exec = async (filename: string, args: string[] | null) => {
  const filepath = getExecPath(filename);
  await setExecutablePermission(filepath);
  return await execFileAsync(filepath, args);
};

export const execWithStdinArg = async (
  filename: string,
  args: string[] | null,
  stdinArg: string | null
) => {
  const filepath = getExecPath(filename);
  await setExecutablePermission(filepath);
  try {
    if (!fs.existsSync(filepath)) {
      throw "shaloa-cui-frontend が存在しません";
    }
    return await execAsync(filepath, args, stdinArg);
  } catch (error) {
    return {
      err: error instanceof Error ? error : new Error(`${error}`),
      stderr: "",
      stdout: ""
    };
  }
};
