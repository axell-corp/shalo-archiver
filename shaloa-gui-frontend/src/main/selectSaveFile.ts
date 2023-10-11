import { app, dialog, FileFilter, IpcMainInvokeEvent } from "electron";

const selectSaveFile = async (_: IpcMainInvokeEvent, filter?: FileFilter[]) => {
  const result = await (async (filter?: FileFilter[]) => {
    try {
      const result = await dialog.showSaveDialog({
        defaultPath: app.getPath("documents"),
        filters: filter
      });
      return result.filePath;
    } catch (e) {
      dialog.showMessageBox({
        type: "error",
        message: "",
        detail: `Error: ${e}`
      });
      return undefined;
    }
  })(filter);

  return result;
};

export default selectSaveFile;
