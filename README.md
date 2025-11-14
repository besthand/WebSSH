## WebSSH

Node.js 版的網頁 SSH 終端機，支援帳號密碼與憑證登入。後端使用 `ssh2` 建立 SSH session，透過 Socket.IO 串流到前端，並以 xterm.js 呈現終端畫面。私鑰提供 OpenSSH / PEM / Base64 PEM / PuTTY (`.ppk`) 自動辨識與轉換。前端採用 Tabler Admin Template 版型，將介面切分為：

- **連線清單**：表格列出所有儲存的主機設定，提供「連線 / 編輯」按鈕；右鍵列可快顯刪除。
- **連線設定編輯頁**：新增或修改主機名稱、Host、Port、使用者與預設驗證方式。
- **Terminal 頁**：顯示 SSH 終端機，左上角圖示可隨時回到連線清單，右上角圖示可切換全螢幕模式。

> 💾 連線設定會儲存主機、埠號、使用者、驗證類型，以及（若為憑證登入）使用者上傳或貼上的私鑰內容，以便日後編輯與連線時自動帶入。所有資料儲存在專案根目錄的 `connections.json`，請視環境需求妥善保護該檔案。

### 安裝

```sh
npm install
```

### 開發模式

```sh
npm run dev
```

服務預設監聽 `http://localhost:8080`，會自動提供 `public/` 中的靜態檔案，可直接在瀏覽器開啟測試。

### 重要環境變數

| 變數 | 預設 | 說明 |
| --- | --- | --- |
| `PORT` | `8080` | HTTP 服務埠號 |
| `ALLOW_ANY_ORIGIN` | `false` | 設為 `true` 時允許任意 CORS / Socket 來源（僅建議測試環境） |
| `ALLOWED_ORIGINS` | _(空)_ | 指定允許的來源清單（以逗號分隔） |
| `SESSION_TTL_MS` | `600000` | SSH session 有效時間 (ms) |
| `CONNECT_TIMEOUT_MS` | `15000` | SSH 連線逾時 |
| `READY_TIMEOUT_MS` | `15000` | SSH ready 事件逾時 |
> ⚠️ 私鑰僅會在瀏覽器端使用 Argon2id + AES-GCM 加密後再送往後端儲存，且必須由使用者提供的 passphrase 導出金鑰；若未提供 passphrase，私鑰不會寫入 `connections.json`，連線時需重新選擇檔案。

### 使用方式

1. 進入「連線清單」，點選「新增連線」填寫 Host、Port、使用者、驗證方式後儲存；或在清單中選取既有項目按「編輯」修改。
2. 清單中的「連線」按鈕會彈出驗證資訊視窗，依預設驗證方式輸入密碼或上傳/貼上私鑰（PPK/PEM 皆可）。若連線設定曾在瀏覽器端以 passphrase 加密儲存私鑰，只需輸入 passphrase 即可自動解密並連線。
3. 確認後呼叫 `/api/session` 建立 SSH，成功即切換至 Terminal 頁並顯示當前連線名稱與 Host。
4. Terminal 透過 Socket.IO 與後端 `/ssh` namespace 串流輸入輸出；左上角圖示可返回連線清單，右上角圖示可切換全螢幕，僅保留終端卷軸。

### 安全建議

- 正式環境需使用 HTTPS/WSS，避免憑證及密碼以明文傳輸。
- 建議限制允許連線的 `host` 清單，防止被濫用為跳板。
- 連線設定中的私鑰僅在使用者提供 passphrase 並於瀏覽器端透過 Argon2id + AES-GCM 加密後才會寫入 `connections.json`（僅儲存密文）；若私鑰無 passphrase，將不被保存。請妥善保護檔案權限並提醒使用者保管 passphrase。
- session 結束時會清空記憶體中的 Buffer，仍可依需求再加強。
- 為系統加上身份驗證、速率限制與審計紀錄，並於生產環境配置監控警示。
