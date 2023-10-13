# shalo-archiver

## 必要なもの

- `msbuild.exe` (バージョン 17.4.1.60106、Visual studio 2022 に付属)
- Node.js（バージョン 18.12.1）
- SHALO AUTH PKCS#11 モジュール
    - https://auth.shalo.jp/ からダウンロードできる
    - インストーラーを実行してシステムにインストールするか、手動で展開して `~\shalo_pkcs11\x64\slpkcs11-vc.dll` に置く
- 環境変数の設定
    - `BOOSTROOT`：Boost のルートディレクトリパス
    - `BOOSTLIB`：Boost のライブラリがあるディレクトリパス

## submodule のクローン

いくつかの依存ライブラリが submodule で管理されています。
ビルドする前に、以下のコマンドを実行して submodule のソースコードをクローンしてください。

```
git submodule update --init --recursive
```

## ビルド

`build.bat` を実行してください。

ビルドが成功すると、`shaloa-gui-frontend/dist` に、インストーラが吐き出されます。
また、`win-unpacked` 以下に、あらかじめ展開されたアプリケーションが吐き出されます。
