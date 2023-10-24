import { ElectronAPI } from "@electron-toolkit/preload";
import { FileFilter, MessageBoxOptions } from "electron";

declare global {
  interface Window {
    electron: ElectronAPI;
    api: {
      selectFile: (shaaOnly: boolean) => Promise<string | undefined>;
      showMessageDialog: (options: MessageBoxOptions) => Promise<number>;
      selectSaveFile: (filter?: FileFilter[]) => Promise<string | undefined>;
      execJsonMode: (params: string) => Promise<{
        err: Error | null;
        stdout: string;
        stderr: string;
      }>;
      autoDecode: (params: string) => Promise<string>;
    };
  }
}
