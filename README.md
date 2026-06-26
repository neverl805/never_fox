# never_fox

**发出去的请求在字节层面就是 Firefox 152** —— 不是模拟,是真的。

`never_fox` 是一个 requests 风格的 Python HTTP 客户端,底层链接 **Firefox 真正的 TLS 引擎 NSS**,所以它的 TLS ClientHello 与真 Firefox 152 **逐字节相同(含 ECH、X25519MLKEM768 后量子组)**,HTTP/2 帧与 header 也与真火狐一致。专为**高并发爬虫 / 风控对抗**设计。

> 一句话原理:Chrome 有 Cronet、Firefox 的网络栈是 NSS(TLS)+ Necko。NSS 开源可独立链接 —— 我们直接链接真 NSS,用逆向出来的 Firefox 152 配置驱动它。这是"模拟"做不到的:curl_cffi 这类能对齐 JA3/JA4,但 ECH 等细节对不上,因为它们用的不是 NSS。

## 为什么它是"真的"

在本地受控 HTTPS 服务器上,让**真 Firefox 152** 和 never_fox 都访问,逐字段对比握手数据,并在 **4 个指纹站(peet.ws / browserleaks / scrapfly / howsmyssl,算法各不同)** 交叉验证:

| 维度 | 与真 Firefox 152 |
|---|---|
| TLS ClientHello 原始字节 | ✅ 0 差异 |
| JA3 / JA3N / JA4 / JA4_o / JA4_r | ✅ 全部一致 |
| HTTP/2 Akamai 指纹(SETTINGS/WINDOW_UPDATE/优先级/伪头序) | ✅ 一致 |
| 所有 HTTP header(名 / 顺序 / 值) | ✅ 一致 |
| ECH、record_size_limit、MLKEM、delegated_credentials | ✅ 一致 |

## 特性

| | |
|---|---|
| **真指纹** | 真 NSS 引擎,ClientHello 字节级 == Firefox 152(含 ECH) |
| **requests 兼容** | `get/post/put/delete/patch/head/options`、`Response`(`.status_code/.ok/.text/.json()/.cookies/.history/.raise_for_status()` …) |
| **异步** | `AsyncSession`,future 驱动,**线程数≈连接数而非请求数** |
| **高并发** | 每 host 多连接池 + HTTP/2 多路复用 + 引用计数防崩 |
| **爬虫刚需** | Cookie 持久化、自动重定向、重试 |
| **代理** | HTTP CONNECT + **SOCKS5**(可认证);目标看到真 FF152,代理只见加密隧道 |
| **限流** | 每 host 限速 + 429/503 指数退避(尊重 `Retry-After`) |
| **HTTP/3** | Alt-Svc 感知,基于真 neqo(实验性,失败自动降级 h2) |

## 环境要求与构建

native 引擎是编译产物,**当前在 macOS arm64 构建**。其它平台(Linux / Intel mac)需在目标机重新构建。

```bash
# 1) 系统依赖
brew install nss nspr nghttp2 brotli zstd          # macOS
# Linux: 安装 libnss3-dev libnspr4-dev libnghttp2-dev libbrotli-dev libzstd-dev

# 2) Python 依赖
pip install hpack brotli zstandard

# 3) 编译原生引擎
bash native/build.sh                                # -> native/libfxtls.dylib

# 4)(可选)打包成自包含,便于拷到同架构机器免依赖运行
python native/bundle.py                             # -> native/vendor/
```

然后把仓库目录加入 `PYTHONPATH` 或在仓库根目录使用:`import never_fox`。

## 快速开始

```python
import never_fox as nf

r = nf.get("https://example.com/", params={"q": "x"})
print(r.status_code, r.ok, r.http_version, r.text[:200])
r.raise_for_status()

r = nf.post("https://httpbin.org/post", json={"hello": "firefox152"})   # 或 data={...} 表单
print(r.json())
```

### Session(Cookie / 重定向 / 连接池)

```python
s = nf.Session()                      # verify=True, h3="auto"
s.get("https://site/login")           # Set-Cookie 自动保存
s.post("https://site/api", data={"a": 1})   # 自动带 Cookie、自动重定向(r.history)
print(s.cookies.as_dict())
s.put(...); s.delete(...); s.patch(...); s.head(...); s.options(...)
s.close()
```

### 异步(高并发)

```python
import asyncio, never_fox as nf

async def main():
    async with nf.AsyncSession() as s:
        # 上千并发共享连接池中的多路复用连接;响应通过 future 等待,
        # 不为每个请求占一个线程(线程数≈连接数,不随请求数增长)。
        rs = await asyncio.gather(*[s.get(f"https://site/p/{i}") for i in range(1000)])
        print(sum(r.ok for r in rs), "ok")

asyncio.run(main())
```

### 爬虫调优(代理 / 限速 / 退避)

```python
s = nf.Session(
    max_connections_per_host=16,    # 每 host 最多连接数
    rate_limit=5,                   # 每 host <= 5 请求/秒(0=不限)
    backoff_retries=3,              # 429/503 指数退避重试,尊重 Retry-After
    retries=3,                      # 连接级重试
    verify=True,                    # 用 Firefox 同款 Mozilla 根证书校验
)

# 代理:HTTP CONNECT 或 SOCKS5(可认证),按会话或按请求,可自由轮换
s = nf.Session(proxy="http://user:pass@proxy:8080")
r = nf.get(url, proxy="socks5://user:pass@10.0.0.1:1080")     # 或 proxies={"https": "..."}
```

`Response`:`.status_code .ok .reason .url .text .content .json() .headers .cookies .history .elapsed .encoding .raise_for_status() .iter_content()`

## 工作原理

```
never_fox/            Python 层
  client.py           Session / Response / 连接池 / Cookie / 重定向 / 限速 / 代理解析
  aio.py              AsyncSession(future 驱动的异步)
  h2conn.py           HTTP/2 多路复用(复刻 Firefox 的 SETTINGS/优先级/伪头序)
  http1.py            HTTP/1.1 回退
  h3.py               HTTP/3(经真 neqo,实验性)
  cookies.py          CookieJar
  _native.py          ctypes 绑定到原生引擎
native/               原生引擎(C,链接真 NSS)
  fxtls_config.h      Firefox 152 的 ClientHello 配置(密码套件/组/签名算法/ECH/证书压缩…)
  fxtls_lib.c         连接 + TLS 握手 + 收发 + 代理(CONNECT/SOCKS5)-> libfxtls.dylib
  bundle.py           把依赖 dylib 收进 vendor/ 并改 @loader_path,便于跨机
harness/              指纹验证脚本(本地抓包对比 + 多站交叉验证)
```

证书用 NSS 内置的 **Mozilla 根证书列表(libnssckbi)** 校验 —— 和 Firefox 同款信任库。

## 已知限制

- 原生库是平台相关二进制:跨 OS / 架构需在目标机重新 `build.sh`(像 Cronet 按平台分发)。Firefox/Linux 是 OS 自洽目标,适合做服务端。
- 会话复用:TLS 1.3 复用握手会带 `pre_shared_key` 扩展,JA3/JA4 与全握手不同 —— **两者都是真 Firefox 指纹**(连接池默认复用同一握手,一般不出现)。
- HTTP/3:实验性,需运行环境 UDP/443 出网;失败自动降级 h2。
- 极端激进限流的服务器(单连接只允许少量流)下,超高并发可能需要调大 `max_connections_per_host`。

## 验证复现

```bash
# 本地起 HTTPS/h2 服务,真 Firefox + never_fox 都访问,逐字段对比
python harness/localcap/diff_h2cap.py        # 看 harness/localcap/FULL_DIFF.md
# 多站交叉验证报告
cat harness/localcap/MULTISITE.md
```

详细逆向与对比过程见 [REPORT.md](REPORT.md)。

## 免责声明

仅用于授权范围内的安全研究、风控对抗测试与合规数据采集。请遵守目标站点的条款与当地法律。
