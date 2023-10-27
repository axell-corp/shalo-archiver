import {
  contextBridge,
  FileFilter,
  ipcRenderer,
  MessageBoxOptions
} from "electron";
import { electronAPI } from "@electron-toolkit/preload";

// Custom APIs for renderer
const api = {
  selectFile: (shaaOnly: boolean) =>
    ipcRenderer.invoke("select-file", shaaOnly),
  showMessageDialog: (options: MessageBoxOptions) =>
    ipcRenderer.invoke("show-message-dialog", options),
  selectSaveFile: (filter?: FileFilter[]) =>
    ipcRenderer.invoke("select-save-file", filter),
  execJsonMode: (params: string) =>
    ipcRenderer.invoke("exec-json-mode", params),
  autoDecode: (params: string) => ipcRenderer.invoke("auto-decode", params)
};

// Use `contextBridge` APIs to expose Electron APIs to
// renderer only if context isolation is enabled, otherwise
// just add to the DOM global.
if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld("electron", electronAPI);
    contextBridge.exposeInMainWorld("api", api);
  } catch (error) {
    console.error(error);
  }
} else {
  // @ts-ignore (define in dts)
  window.electron = electronAPI;
  // @ts-ignore (define in dts)
  window.api = api;
}
