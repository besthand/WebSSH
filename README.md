## WebSSH

Node.js 版的網頁 SSH 終端機，支援帳號密碼與憑證登入。後端使用 `ssh2` 建立 SSH session，透過 Socket.IO 串流到前端，並以 xterm.js 呈現終端畫面。私鑰提供 OpenSSH / PEM / Base64 PEM / PuTTY (`.ppk`) 自動辨識與轉換。前端採用 Tabler Admin Template 版型，將介面切分為：

- **連線清單**：表格列出所有儲存的主機設定，提供「連線 / 編輯」按鈕；右鍵列可快顯刪除。
- **連線設定編輯頁**：新增或修改主機名稱、Host、Port、使用者與預設驗證方式。
- **Terminal 頁**：顯示 SSH 終端機，左上角圖示可隨時回到連線清單，右上角圖示可切換全螢幕模式。

> NOTE: 所有連線設定（含私鑰）都僅存放在瀏覽器的 LocalStorage，後端伺服器不會保留任何連線資料。
>
> WARNING: 僅在使用者提供私鑰密碼時才會將私鑰加密後儲存；若無密碼，必須於每次連線時重新提供私鑰。
> 💾 連線設定會儲存主機、埠號、使用者與預設驗證方式；若提供私鑰並輸入密碼，會以瀏覽器 LocalStorage 方式加密保存。伺服器端不會保留任何連線資料。

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
> WARNING: 只有在使用者提供 passphrase（表示私鑰已受密碼保護）時，才會將私鑰加密後寫入瀏覽器 LocalStorage；未設 passphrase 的私鑰不會被儲存。

### 使用方式

1. 進入「連線清單」，點選「新增連線」填寫 Host、Port、使用者、驗證方式。若選擇憑證驗證且提供私鑰與密碼，瀏覽器會直接使用 PBKDF2 + AES-GCM 加密後寫入 LocalStorage（僅在本機）。
2. 清單中的「連線」按鈕會彈出驗證視窗，依驗證方式輸入密碼或提供私鑰。若該連線曾保存加密私鑰，只要輸入當初設定的密碼即可解密私鑰並連線。
3. 確認後呼叫 `/api/session` 建立 SSH，成功即切換至 Terminal 頁並顯示當前連線名稱與 Host。
4. Terminal 透過 Socket.IO 與後端 `/ssh` namespace 串流輸入輸出；左上角圖示可返回連線清單，右上角圖示可切換全螢幕，僅保留終端卷軸。

### 安全建議

- 正式環境需使用 HTTPS/WSS，避免憑證及密碼以明文傳輸。
- 建議限制允許連線的 `host` 清單，防止被濫用為跳板。
- 私鑰僅會保存在瀏覽器端 LocalStorage，並以使用者輸入的密碼透過 PBKDF2 + AES-GCM 加密後再儲存；伺服器不保存任何連線資料。未提供密碼的私鑰不會被保存。
- session 結束時會清空記憶體中的 Buffer，仍可依需求再加強。
- 為系統加上身份驗證、速率限制與審計紀錄，並於生產環境配置監控警示。
