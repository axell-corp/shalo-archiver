const checker = require("license-checker");
const path = require("path");
const fs = require("fs");
const iconv = require("iconv-lite");

const OUT_DIR = "out";
const DIST_DIR = "dist";
const LICENSE_FILE = "LICENSE";
const LICENSE_LIST = "license_list.csv";

const licensePath = path.join(OUT_DIR, LICENSE_FILE);
const csvPath = path.join(DIST_DIR, LICENSE_LIST);

const customFormat = {
  name: "",
  version: "",
  description: false,
  repository: "",
  publisher: false,
  email: false,
  url: false,
  licenses: "",
  licenseFile: "",
  licenseText: "",
  licenseModified: false,
  private: false,
  path: false,
  copyright: false,
  noticeFile: false
};
const override = require("../override_osslic").module;
const overrideNames = override.map((v) => v.name);

checker.init(
  {
    start: ".",
    production: true,
    customFormat: customFormat
  },
  (err, ret) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }

    const packageNames = [];
    const licenses = [];
    Object.keys(ret).forEach((key) => {
      licenses.push(ret[key]);
      packageNames.push(ret[key].name);
    });
    override.forEach((v) => {
      if (!packageNames.includes(v.name)) {
        licenses.push(v);
      }
    });

    let text = "";
    let csvText = "";
    for (const lic of licenses) {
      if (lic.name === process.env.npm_package_name) continue;

      text += `${lic.name} ${lic.version}\n`;
      text += "-----\n";
      text += overrideNames.includes(lic.name)
        ? override.filter((v) => v.name === lic.name)[0].licenseText
        : lic.licenseText;
      text += "\n\n\n\n";

      const url = `https://www.npmjs.com/package/${lic.name}`;
      csvText += `${lic.name},${lic.version},${url},${lic.licenses},\n`;

      if (
        !containsLicense(lic.licenseFile) &&
        !overrideNames.includes(lic.name)
      ) {
        console.log(`${lic.name} has no LICENSE file. ${url}`);
      }
    }

    if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });
    if (!fs.existsSync(DIST_DIR)) fs.mkdirSync(DIST_DIR, { recursive: true });

    fs.writeFileSync(licensePath, text, { encoding: "utf-8" });
    fs.writeFileSync(csvPath, iconv.encode(csvText, "CP932"));
  }
);

/**
 * パスに "LICENSE" が含まれているか判定
 * @param {string} licenseFile LICENSE ファイルのパス
 * @return {boolean}
 */
function containsLicense(licenseFile) {
  return /[/\\]LICEN[SC]E(-MIT)?(\.(txt|md|markdown|BSD))?$/i.test(licenseFile);
}
