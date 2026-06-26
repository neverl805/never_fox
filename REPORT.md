# Firefox 152 真发包引擎 — 实测对比报告

> 路径 A 落地:用 **curl_cffi(真 NSS 构建)** 作为 Firefox 发包引擎,与本机 **真 Firefox 152.0.2** 做 socket 层逐字节对比,定位差异并调校至一致。
> 全部数字均为本机实测(macOS 26.5.1 / arm64),非引用。

## 0. 实验环境

| 项 | 值 |
|---|---|
| 真浏览器(基准) | Firefox **152.0.2** `/Applications/Firefox.app`(NSS) |
| 引擎 | `curl_cffi 0.15.0`,profile `firefox147`(其最新 FF 档),底层真 NSS |
| 主机 | macOS 26.5.1,Apple Silicon (arm64),Python 3.14 |
| 采集法 | 自建 **ClientHello sink**(裸 socket 抓真实握手字节,不依赖浏览器自动化/抓包/sudo) |
| 第三方校验 | `tls.peet.ws`(独立计算 JA3/JA4/Akamai,用于交叉验证 sink) |

**采集器可信度已验证**:同一引擎,sink 算出的 `ja3=6f7889b9…`、`ja4=t13d1717h2_5b57614c22b0_3cbfd9057e0d` 与 peet.ws 独立返回值**完全一致**;真 FF152 的 `ja3=6447ab08…` 也与 peet.ws 自报值一致。解析正确。

---

## 1. 总结论

| 协议层 | 引擎(firefox147,默认) vs 真 FF152 | 可否调平 |
|---|---|---|
| **HTTP/2(Akamai)** | ✅ **完全相同**(`6ea73faa8fc5aac76bded7bd238f6433`) | 无需调,开箱即对 |
| **TLS ClientHello(JA3/JA4)** | ❌ 3 处差异 | 2 处可调平→JA3/JA4 完全一致;1 处(ECH)暂不可调 |
| **HTTP header / UA** | ⚠️ UA 写的是 147 | 改 `default_headers` 即可 |

> **核心成果:经 2 处覆盖调校后,引擎的 ClientHello 与真 Firefox 152 的 JA3、JA4 完全相同(`6447ab08…` / `t13d1617h2_86a278354501_3cbfd9057e0d`),HTTP/2 Akamai 指纹本就相同。剩 1 处 ECH GREASE 载荷长度差异(JA3/JA4 看不到),需 L3 真浏览器才能彻底消除。**

---

## 2. TLS ClientHello 逐字段对比

完全一致的层(引擎默认即对):
- **extensions**(17 个,顺序一致)、**supported_groups**(7 个)、**key_share**(3 组)、**signature_algorithms**(11 个)、**supported_versions**、**ec_point_formats**、**ALPN**(h2, http/1.1)
- **FF152 关键标记全部命中**:`X25519MLKEM768`(0x11ec,在 groups 和 key_share 中)、`ffdhe2048/3072`、`record_size_limit` 存在、`delegated_credentials`、`ECH(0xfe0d)`、`session_ticket`;且 **NSS 默认不发 GREASE**(FF 和引擎都没有,符合 Firefox 行为)

差异的 3 处:

### 差异① 密码套件多 1 个(稳定,可调平)
- 引擎 17 个,FF152 **16 个**;引擎在第 10 位多了 `0xc009 ECDHE_ECDSA_AES128_CBC_SHA`。
- FF152 实际套件(有序):
  `1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c00a,c013,c014,009c,009d,002f,0035`
- **修复**:`ja3=<FF152 的 ja3 串>` 覆盖 → 引擎丢弃 c009。

### 差异② record_size_limit 值不同(稳定,可调平)
- FF152 = `0x4001`(16385,标准 2¹⁴+1);引擎 = `0x0FA1`(4001,curl 用自身缓冲推导的值)。
- **修复**:`extra_fp=ExtraFingerprints(tls_record_size_limit=16385)`。

### 差异③ ECH GREASE 载荷长度(随设备/实现,**暂不可调平**)
- 多次采样实测:**真 FF152 恒为 281 字节**(3/3 样本一致);**引擎在 186 / 218 间跳变**,永远到不了 281。
- ECH 内容本身是随机加密载荷(应忽略),但**载荷长度**对 Firefox 是稳定特征,curl_cffi 未暴露该旋钮,无法对齐。
- 影响面:**不进 JA3/JA4**(二者只看扩展 0xfe0d 是否存在),只有"解析 ECH 长度"的检测器能区分。

---

## 3. 调校结果(把引擎调成 FF152)

```python
from curl_cffi import requests
from curl_cffi.requests import ExtraFingerprints

FF152_JA3 = ("771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-"
             "49171-49172-156-157-47-53,"
             "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,"
             "4588-29-23-24-25-256-257,0")

r = requests.get(url,
    impersonate="firefox147",
    ja3=FF152_JA3,                                            # 修差异①
    extra_fp=ExtraFingerprints(tls_record_size_limit=16385), # 修差异②
    headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; "
             "rv:152.0) Gecko/20100101 Firefox/152.0", ...}, # 修 UA
)
```

实测:
| | 真 FF152 | 调校前引擎 | 调校后引擎 |
|---|---|---|---|
| JA3 | `6447ab086255d194909d4013b1a89e87` | `6f7889b9fb1a62a9577e685c1fcfa919` | **`6447ab086255d194909d4013b1a89e87`** ✅ |
| JA4 | `t13d1617h2_86a278354501_3cbfd9057e0d` | `t13d1717h2_5b57614c22b0_…` | **`t13d1617h2_86a278354501_3cbfd9057e0d`** ✅ |
| Akamai H2 | `6ea73faa…` | `6ea73faa…` ✅ | `6ea73faa…` ✅ |

调校后,结构归一化字节对比(掩码 random/key_share/ECH)→ **仅剩 ECH 载荷长度的连带差异**,无其它结构差异。

---

## 4. HTTP/2 层(Akamai)— 开箱即对

引擎与 FF152 的 Akamai 指纹**逐字段相同**:
```
1:65536;2:0;4:131072;5:16384 | 12517377 | 0 | m,p,a,s
└ SETTINGS:                     └WINDOW_   └prio └伪头序 = :method :path
  HEADER_TABLE_SIZE=65536         UPDATE          :authority :scheme
  ENABLE_PUSH=0                   =12517377                 (Firefox 特征序)
  INITIAL_WINDOW_SIZE=131072
  MAX_FRAME_SIZE=16384
hash = 6ea73faa8fc5aac76bded7bd238f6433  (两边相同)
```
注:本机 FF152 / 引擎在此场景 priority 字段为 `0`(无独立 PRIORITY 帧)。若目标站点触发 Firefox 的 RFC 9218 `PRIORITY_UPDATE` 行为,需用 `extra_fp` 的 `http2_*` 旋钮再核;curl_cffi 已暴露 `http2_stream_weight/exclusive/no_priority`。

---

## 5. 残差与建议

| 残差 | 性质 | 处理 |
|---|---|---|
| ECH GREASE 载荷长度(FF 281 / 引擎 186~218) | 真实、稳定特征,curl_cffi 无旋钮 | 面对 ECH 长度检测时改走 **L3 真无头 Firefox** 发包后端;或自编译 curl-impersonate 时 patch NSS 的 ECH GREASE 长度 |
| UA 版本号 147 vs 152 | 配置项 | 覆盖 `User-Agent` 及 Accept* 头为 FF152 值 |
| HTTP/2 RFC 9218 优先级 | 视站点而定 | 用 `http2_*` extra_fp 旋钮按真机抓包对齐 |

**部署提示**:Firefox/Linux 是自洽组合,本引擎放 Linux 服务器无 TLS↔TCP 的 OS 矛盾(区别于 Safari)。Firefox 约 4 周一版,建议把本 harness 接入回归:每次 FF 升级 → 重抓真机 → 重跑 `diff_report.py`。

---

## 6. 复现实验

```bash
PY=/Users/neverland/miniconda3/envs/spider/bin/python3
cd /Users/neverland/firefox-tls-engine
$PY harness/drive_engine.py --target firefox147   # 抓引擎 ClientHello + peet 指纹
$PY harness/capture_firefox.py 8444               # 抓真 FF152 ClientHello
$PY harness/diff_report.py                        # 生成逐字段 diff
$PY harness/tune_engine.py                        # 调校引擎→验证 JA3/JA4 对齐
$PY harness/stability_and_verify.py               # 多采样稳定性 + ECH 分析
```
