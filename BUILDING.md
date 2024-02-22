# shaloArchiver のビルド

本アプリケーションをビルドする手順を説明します。

## 必要なもの

- `msbuild.exe`（バージョン 17.4.1.60106、Visual Studio 2022 に付属）
- Node.js（バージョン 18.12.1）
- Boost C++ Libraries（バージョン 1.83）
- SHALO AUTH PKCS#11 モジュール
    - https://auth.shalo.jp/ からダウンロードできます
    - インストーラーを実行してシステムにインストールするか、手動で展開して `~\shalo_pkcs11\x64\slpkcs11-vc.dll` に置いてください

## submodule のクローン

いくつかの依存ライブラリが submodule で管理されています。
ビルドする前に、以下のコマンドを実行して submodule のソースコードをクローンしてください。

```
git submodule update --init --recursive
```

## 環境変数の設定

以下の環境変数を設定する必要があります。

- `BOOSTROOT`：Boost のルートディレクトリパス
    - 設定例：`C:\boost\build\include\boost-1_83`
- `BOOSTLIB`：Boost のライブラリがあるディレクトリパス
    - 設定例：`C:\boost\build\lib`

## ビルド

Developer Command Prompt for VS 2022 を開き、`build.bat` を実行してください。

ビルドが成功すると、`shaloa-gui-frontend/dist` に、実行可能ファイル形式のインストーラが出力されます。
また、`shaloa-gui-frontend/dist/win-unpacked` 以下に、あらかじめ展開された形式のアプリケーションが出力されます。
