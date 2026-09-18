# HostTraceAI LOGO 规范

## 核心概念

图标以圆角六边形表达 Host 的边界与稳定，内部用负空间形成字母 H。贯穿 H 的三节点折线表达 Trace 链路，右上四角星表达 AI 分析核心。

## 标准颜色

| 场景 | 主图形 | 轨迹 | AI 星芒 | 背景 |
| --- | --- | --- | --- | --- |
| 浅色 | `#0B1F33` | `#0066FF` | `#00B8D9` | `#F7F9FC` |
| 深色 | `#F8FAFC` | `#4DA3FF` | `#22D3EE` | `#0B1020` |

LOGO 不依赖渐变、阴影或发光效果。动效仅用于数字界面的品牌入场，不改变静态识别。

## 尺寸与安全区

- 导航栏标准图标：44px。
- 数字场景最小尺寸：24px。
- 16px favicon 使用简化版，移除 AI 星芒和中间节点。
- 图标四周至少保留图标高度 0.5 倍的安全区；紧凑 UI 中不得低于 0.25 倍。

## 资产

- `hosttrace-logo.svg`：默认主版。
- `hosttrace-logo-light.svg`：浅色界面。
- `hosttrace-logo-dark.svg`：深色界面。
- `hosttrace-logo-mono.svg`：可通过 `currentColor` 控制的单色版。
- `hosttrace-logo-reversed.svg`：固定反白版。
- `hosttrace-favicon.svg`：16–32px 简化版。
- `hosttrace-logo-animated.svg`：1.2 秒内完成的轨迹与 AI 星芒入场动效，支持 `prefers-reduced-motion`。
- `hosttrace-logo-light-512.png`：浅色版透明 PNG。
- `hosttrace-logo-dark-512.png`：深色版透明 PNG。
- `hosttrace-app-icon-180.png`：Apple Touch Icon。
- `hosttrace-favicon-32.png`：32px PNG favicon 备用文件。

## 禁止事项

- 不拉伸、旋转或改变图形比例。
- 不添加投影、外发光和非品牌渐变。
- 不改变节点数量、轨迹方向或星芒位置。
- 不在复杂图片上直接使用彩色版；应使用单色版并保证对比度。
