import { dialog, IpcMainInvokeEvent, MessageBoxOptions } from "electron";

const showMessageDialog = async (
  _: IpcMainInvokeEvent | undefined,
  options: MessageBoxOptions
) => {
  const result = await dialog.showMessageBox(options);
  return result.response;
};

export default showMessageDialog;
