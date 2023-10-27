import { dialog, IpcMainInvokeEvent } from "electron";

const selectFile = async (_: IpcMainInvokeEvent, shaaOnly: boolean) => {
  const result = await (async () => {
    try {
      return await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: shaaOnly
          ? [
              {
                extensions: ["shaa"],
                name: "SHALO AUTH Archive file"
              }
            ]
          : undefined
      });
    } catch (e) {
      console.error(`Error: ${e}`);
      return undefined;
    }
  })();

  return result?.filePaths[0];
};

export default selectFile;
