# 企业AI应用与技能需求调查问卷系统

在线问卷调查系统，Flask + SQLite 后端，支持云端独立部署。

## 功能特性

- 📋 问卷填报（5部分，含B1智能跳题逻辑）
- 📊 数据看板（Chart.js 可视化统计）
- 📈 趋势分析（28天趋势图）
- 🔀 交叉分析（行业×AI率、规模×AI率）
- 📥 CSV 数据导出
- 🔒 IP 提交限制 + 速率限制
- ⏱️ 问卷开关 + 时间窗口控制
- 💾 前端草稿自动保存

## 文件结构

```
survey-system/
├── server.py              # Flask 后端 (v2.7)
├── requirements.txt       # Python 依赖
├── render.yaml            # Render.com 部署配置
├── static/
│   ├── index.html         # 问卷前端
│   └── admin.html         # 管理后台
└── .gitignore
```

## 管理密码

```
admin2026
```

## 部署方式

### 方式一：本地运行

```bash
pip install flask
python server.py
# 问卷: http://localhost:8080/
# 后台: http://localhost:8080/admin
```

### 方式二：云端部署 (推荐) 🌐

**👉 一键部署到 Render.com（点击下方按钮）：**

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/yx4wx95hf4-eng/ai-survey-system-v2)

> 点击按钮 → 授权 GitHub → 自动读取 render.yaml → 2分钟完成部署  
> 部署后将获得公开 URL（如 `https://ai-survey-v2.onrender.com/`）  
> **任何人用手机/电脑浏览器即可访问，无需微信、无需电脑在线！**

部署后公开访问地址：
- 📋 问卷前台：`https://你的应用名.onrender.com/`
- ⚙️ 管理后台：`https://你的应用名.onrender.com/admin`
- 🔑 管理密码：`admin2026`
