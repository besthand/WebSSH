# Plan Mode 功能實現指南

## 功能概述
Plan Mode 讓 AI Agent 先規劃執行步驟，等待用戶確認後再執行，並實時顯示進度。

## 已完成的 UI 部分
✅ 執行計劃顯示區域（可摺疊）
✅ 計劃步驟樣式（pending/running/completed/failed）
✅ Plan Mode 切換開關
✅ 步驟進度動畫

## JavaScript 實現要點

### 1. 在 `agent.js` 開頭添加 DOM 元素引用：
```javascript
const planModeToggle = document.getElementById('plan-mode-toggle');
const executionPlanSection = document.getElementById('execution-plan-section');
const executionPlanContent = document.getElementById('execution-plan-content');
const collapsePlanBtn = document.getElementById('collapse-plan-btn');
```

### 2. 添加全局狀態變數：
```javascript
let planMode = false;
let currentPlan = null;
let currentStepIndex = 0;
```

### 3. 修改 AI System Prompt（添加計劃模式支援）：
當 `planMode === true` 時，system prompt 應包含：

```
**PLAN MODE ENABLED**
For this task, you MUST first create an execution plan before taking any action.

PLANNING PHASE OUTPUT:
{
  "mode": "planning",
  "thought": "分析任務需求...",
  "plan": {
    "title": "任務標題",
    "steps": [
      {
        "id": 1,
        "title": "步驟標題",
        "description": "步驟詳細說明",
        "command": "要執行的指令（可選）"
      }
    ]
  },
  "answer": "向用戶說明計劃內容並請求確認"
}

After user confirms, you will execute each step one by one.

EXECUTION PHASE OUTPUT (參考計劃):
{
  "mode": "executing",
  "thought": "執行步驟 X: ...",
  "stepId": 1,
  "command": "實際指令",
  "answer": "步驟執行說明（可選）"
}

When all steps完成, set command to "DONE".
```

### 4. 實現計劃顯示函數：
```javascript
function displayPlan(plan) {
    currentPlan = plan;
    currentStepIndex = 0;
    executionPlanContent.innerHTML = '';
    
    plan.steps.forEach((step, index) => {
        const stepEl = document.createElement('div');
        stepEl.className = 'plan-step pending';
        stepEl.id = `plan-step-${step.id}`;
        stepEl.innerHTML = `
            <div class="plan-step-icon">${index + 1}</div>
            <div class="plan-step-content">
                <div class="plan-step-title">${step.title}</div>
                <div class="plan-step-description">${step.description}</div>
            </div>
        `;
        executionPlanContent.appendChild(stepEl);
    });
    
    // 顯示確認按鈕
    const actionsEl = document.createElement('div');
    actionsEl.className = 'plan-confirm-actions';
    actionsEl.innerHTML = `
        <button class="btn btn-sm btn-ghost-danger" id="plan-reject-btn">
            <i class="ti ti-x me-1"></i>拒絕
        </button>
        <button class="btn btn-sm btn-primary" id="plan-confirm-btn">
            <i class="ti ti-check me-1"></i>確認執行
        </button>
    `;
    executionPlanContent.appendChild(actionsEl);
    
    // 顯示計劃區域
    executionPlanSection.classList.remove('d-none');
    
    // 綁定按鈕事件
    document.getElementById('plan-confirm-btn').addEventListener('click', confirmPlan);
    document.getElementById('plan-reject-btn').addEventListener('click', rejectPlan);
}
```

### 5. 更新步驟狀態：
```javascript
function updateStepStatus(stepId, status) {
    const stepEl = document.getElementById(`plan-step-${stepId}`);
    if (!stepEl) return;
    
    // 移除所有狀態 class
    stepEl.classList.remove('pending', 'running', 'completed', 'failed');
    // 添加新狀態
    stepEl.classList.add(status);
    
    // 更新圖標
    const icon = stepEl.querySelector('.plan-step-icon');
    if (status === 'running') {
        icon.innerHTML = '⟳';
    } else if (status === 'completed') {
        icon.innerHTML = '✓';
    } else if (status === 'failed') {
        icon.innerHTML = '✕';
    }
}
```

### 6. 修改 `runAgent` 函數支持計劃模式：
```javascript
async function runAgent(task) {
    // ... 現有代碼 ...
    
    // 在 system prompt 中加入 plan mode 指示
    const systemPrompt = planMode ? 
        `${原有的system prompt}\n\n${plan mode instructions}` :
        原有的system prompt;
    
    // 在主循環中處理計劃響應
    for (let turn = 0; turn < maxTurns; turn++) {
        // ... 呼叫 AI ...
        
        if (plan.mode === 'planning') {
            // 顯示計劃並等待確認
            displayPlan(plan.plan);
            // 暫停 Agent 執行，等待用戶確認
            return;
        } else if (plan.mode === 'executing') {
            // 更新步驟狀態
            if (plan.stepId) {
                updateStepStatus(plan.stepId, 'running');
            }
            
            // 執行指令
            await executeCommand(plan.command, plan.thought);
            
            // 標記為完成
            if (plan.stepId) {
                updateStepStatus(plan.stepId, 'completed');
                currentStepIndex++;
            }
        }
    }
}
```

### 7. 計劃確認/拒絕處理：
```javascript
async function confirmPlan() {
    // 移除確認按鈕
    document.querySelector('.plan-confirm-actions')?.remove();
    
    // 添加系統消息
    addLog('system', `✅ 計劃已確認，開始執行 ${currentPlan.steps.length} 個步驟...`);
    
    // 繼續執行 agent（帶著計劃）
    continueAgentWithPlan();
}

function rejectPlan() {
    addLog('system', '❌ 用戶拒絕了執行計劃');
    // 隱藏計劃
    executionPlanSection.classList.add('d-none');
    currentPlan = null;
    agentRunning = false;
    updateAgentUI(false);
}
```

## 更新建議的完整流程

1. 用戶勾選「計劃模式」
2. 輸入任務並點擊「執行」
3. AI 分析任務並生成執行計劃
4. 顯示計劃在 UI 上，等待確認
5. 用戶確認後，AI 逐步執行計劃
6. 每個步驟執行時更新視覺狀態
7. 所有步驟完成後標記任務完成

## 下一步
由於完整實現涉及較多代碼修改，我建議：
1. 先測試 UI 是否正常顯示
2. 逐步實現 JavaScript 邏輯
3. 測試計劃生成和確認流程
4. 測試執行過程中的進度更新
