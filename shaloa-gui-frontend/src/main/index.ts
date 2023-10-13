import { app, shell, BrowserWindow, ipcMain } from "electron";
import { join } from "path";
import { electronApp, optimizer, is } from "@electron-toolkit/utils";
import icon from "../../resources/shaloArchiver-icon.png?asset";
import selectFile from "./selectFile";
import showMessageDialog from "./showMessageDialog";
import selectSaveFile from "./selectSaveFile";
import execJsonMode from "./execJsonMode";
import autoDecode from "./autoDecode";

function createWindow(): void {
  // Create the browser window.
  const mainWindow = new BrowserWindow({
    width: 400,
    height: 750,
    show: false,
    autoHideMenuBar: true,
    resizable: false,
    ...(process.platform === "linux" ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, "../preload/index.js"),
      sandbox: false
    }
  });

  ipcMain.handle("select-file", selectFile);
  ipcMain.handle("show-message-dialog", showMessageDialog);
  ipcMain.handle("select-save-file", selectSaveFile);
  ipcMain.handle("exec-json-mode", execJsonMode);
  ipcMain.handle("auto-decode", autoDecode);

  mainWindow.on("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url);
    return { action: "deny" };
  });

  const filepath = (() => {
    if (process.argv[1] && process.argv[1] !== ".") {
      mainWindow.setSize(400, 300, false);

      // デバッグ用
      if (process.argv[2]) {
        return process.argv[2];
      }

      return process.argv[1];
    } else {
      return "";
    }
  })();

  // HMR for renderer base on electron-vite cli.
  // Load the remote URL for development or the local html file for production.
  if (is.dev && process.env["ELECTRON_RENDERER_URL"]) {
    mainWindow.loadURL(
      process.env["ELECTRON_RENDERER_URL"] + "?filepath=" + filepath
    );
  } else {
    mainWindow.loadFile(join(__dirname, "../renderer/index.html"), {
      query: {
        filepath: filepath
      }
    });
  }
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.whenReady().then(() => {
  // Set app user model id for windows
  electronApp.setAppUserModelId("jp.co.axell.shalo.archiver");

  // Default open or close DevTools by F12 in development
  // and ignore CommandOrControl + R in production.
  // see https://github.com/alex8088/electron-toolkit/tree/master/packages/utils
  app.on("browser-window-created", (_, window) => {
    if (process.env.NODE_ENV === "development")
      optimizer.watchWindowShortcuts(window);
  });

  createWindow();

  app.on("activate", function () {
    // On macOS it's common to re-create a window in the app when the
    // dock icon is clicked and there are no other windows open.
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Quit when all windows are closed, except on macOS. There, it's common
// for applications and their menu bar to stay active until the user quits
// explicitly with Cmd + Q.
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

// In this file you can include the rest of your app"s specific main process
// code. You can also put them in separate files and require them here.
