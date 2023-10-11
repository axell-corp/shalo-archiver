import { randomUUID } from "crypto";
import { app, BrowserWindow, IpcMainInvokeEvent } from "electron";
import { join } from "path";
import execJsonMode from "./execJsonMode";
import { readdir, unlink } from "fs/promises";
import { exec, execSync } from "child_process";
import showMessageDialog from "./showMessageDialog";
import { watch } from "chokidar";
import { z } from "zod";

const validateParams = <T extends z.ZodRawShape>(
  Schema: z.ZodObject<T>,
  params: string
) => Schema.safeParse(JSON.parse(params));

const autoDecode = async (invoke_event: IpcMainInvokeEvent, params: string) => {
  const ParsedParams = z.object({
    operation: z.string(),
    properties: z.object({
      inPath: z.string(),
      outPath: z.string(),
      pin: z.string()
    })
  });

  const parsedParams = validateParams(ParsedParams, params);

  if (!parsedParams.success) {
    return "復号に失敗しました: 実行結果の解析に失敗しました";
  }

  const tmpPath = app.getPath("temp");

  const file_uuid = randomUUID();
  parsedParams.data.properties.outPath = join(tmpPath, file_uuid);

  const result = await execJsonMode(
    invoke_event,
    JSON.stringify(parsedParams.data)
  );

  if (result.stdout === "" && result.err !== null) {
    return result.err.message;
    //error
  }

  const ParsedStdout = z.object({
    result: z.string(),
    detail: z.string()
  });

  const parsedStdout = validateParams(ParsedStdout, result.stdout);

  if (!parsedStdout.success) {
    return "復号に失敗しました: 実行結果の解析に失敗しました";
  }

  if (parsedStdout.data.result !== "SHALOA_RESULT_SUCCESS") {
    return "復号に失敗しました: " + parsedStdout.data.detail;
  }

  const keyId = parseInt(parsedStdout.data.detail);

  const files = await readdir(tmpPath);
  const tmp_file_name = files.find((file) => file.includes(file_uuid));
  if (tmp_file_name === undefined) {
    return "Temporary file not found";
  }

  const window = BrowserWindow.fromWebContents(invoke_event.sender);
  if (window === null) {
    return "Browser Window not found";
  }

  window.hide();

  const tmp_file_path = join(tmpPath, tmp_file_name);

  let application_closed = false;

  switch (process.platform) {
    case "win32":
      exec(`cmd.exe /C start /WAIT ${tmp_file_path}`, async () => {
        application_closed = true;
      });
      break;
    case "darwin":
      execSync("open " + tmp_file_path);
      break;
    case "linux":
      execSync("xdg-open " + tmp_file_path);
      break;
    default:
      return "Unsupported platform";
  }

  const watcher = watch(tmp_file_path);

  watcher.on("change", async () => {
    const encode_result = await execJsonMode(
      invoke_event,
      JSON.stringify({
        operation: "Encode",
        properties: {
          inPath: tmp_file_path,
          outPath: parsedParams.data.properties.inPath,
          keyId
        }
      })
    );

    const dialog_message = (() => {
      const parsedStdout = validateParams(ParsedStdout, encode_result.stdout);

      if (!parsedStdout.success) {
        return "復号に失敗しました: 実行結果の解析に失敗しました";
      }
      if (parsedStdout.data.result === "SHALOA_RESULT_SUCCESS") {
        return "再暗号化に成功しました";
      } else {
        return "再暗号化に失敗しました：" + parsedStdout.data.detail;
      }
    })();

    await showMessageDialog(invoke_event, {
      type: "info",
      detail: dialog_message,
      message: "",
      noLink: true
    });

    if (application_closed) {
      await unlink(tmp_file_path);
      app.quit();
    }
  });

  return "";
};

export default autoDecode;
