import { dialog, IpcMainInvokeEvent } from "electron";

const selectFile = async (_: IpcMainInvokeEvent, shlaOnly: boolean) => {
  const result = await (async () => {
    try {
      return await dialog.showOpenDialog({
        properties: ["openFile"],
        filters: shlaOnly
          ? [
              {
                extensions: ["shla"],
                name: "SHALO Archive"
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
