import { IpcMainInvokeEvent } from "electron";
import { execWithStdinArg } from "./exec";

export type JsonModeResult =
  | "SHALOA_RESULT_SUCCESS"
  | "SHALOA_RESULT_ERROR_INVALID_ARGUMENT"
  | "SHALOA_RESULT_ERROR_FILE_IO"
  | "SHALOA_RESULT_ERROR_PKCS_TOKEN"
  | "SHALOA_RESULT_ERROR_READ_MODULE"
  | "SHALOA_RESULT_ERROR_READ_FUNCTION_LIST"
  | "SHALOA_RESULT_ERROR_INVALID_FILE"
  | "SHALOA_RESULT_ERROR_CNG_OPERATION"
  | "SHALOA_RESULT_ERROR_KEY_NOT_FOUND"
  | "SHALOA_RESULT_ERROR_INTERNAL"
  | "SHALOA_RESULT_ERROR_JSON_MODE";

const execJsonMode = async (_: IpcMainInvokeEvent, params: string) => {
  const result = await execWithStdinArg(
    "shaloa-cui-frontend",
    ["--json"],
    params
  );
  return result;
};

export default execJsonMode;
