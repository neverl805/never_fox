# 多站交叉指纹对比 — fxreq vs 真 Firefox 152

不同站点用不同的指纹算法,逐站验证 fxreq 与真 Firefox 152 一致。
基础事实:本地全链路抓取已证明 **fxreq 的 ClientHello 与 FF152 逐字节相同(0 结构差异)**,
所以任何从 ClientHello 派生的指纹(无论哪种算法)必然一致;以下为多站经验证实。

## 1. tls.peet.ws (标准 JA3/JA4 + Akamai + peetprint)
| 指标 | 真 FF152 | fxreq | |
|---|---|---|---|
| ja3 | `6447ab086255d194909d4013b1a89e87` | 同 | ✅ |
| ja4 | `t13d1617h2_86a278354501_3cbfd9057e0d` | 同 | ✅ |
| akamai | `6ea73faa8fc5aac76bded7bd238f6433` | 同 | ✅ |
| peetprint | `fd4547eeb41f073156b7bc8125a79a3c` | 同 | ✅ |

## 2. tls.browserleaks.com/json （站点侧直接读真 FF152 截图）
| 指标 | 真 FF152(浏览器实测) | fxreq | |
|---|---|---|---|
| ja3_hash | `6447ab086255d194909d4013b1a89e87` | 同 | ✅ |
| ja3n_hash | `8099457c290ccfe8c6d958826c26b023` | 同 | ✅ |
| ja4 | `t13d1617h2_86a278354501_3cbfd9057e0d` | 同 | ✅ |
| ja4_o | `t13d1617h2_d6294ab6b85e_df135d36b6d5` | 同 | ✅ |
| ja4_ro | `t13d1617h2_1301,1303,1302,…` | 同 | ✅ |
| akamai_hash | `6ea73faa8fc5aac76bded7bd238f6433` | 同 | ✅ |

## 3. tools.scrapfly.io/api/fp/ja3 （**非标准算法**：ja3 用 version=772，ja4 扩展计数=15）
| 指标 | 真 FF152(由 FF 原始字节按 scrapfly 算法自算) | fxreq(站点返回) | |
|---|---|---|---|
| ja3 version 字段 | **772**(= max supported_versions，非 peet 的 771) | 772 | ✅ |
| ja3_digest | `f2a56a7ef6a484d83a2ea9ab8f35c5d3` | `f2a56a7ef6a484d83a2ea9ab8f35c5d3` | ✅ |
| ja3n_digest | `f74eedceb2460d89dd6a6adf6f68610e` | 同 | ✅ |
| ja4 | `t13d1615h2_86a278354501_eaf17881ff57`（ext计数15） | 同 | ✅ |
| scrapfly_fp | `version:772\|ch_ciphers:…\|psk:1\|…` | 同 | ✅ |

> 印证了"不同站算法不同":scrapfly 的 ja3 用 772、ja4 扩展计数 15、ja4_r 把 sigalgs 排了序——
> 都和 peet/browserleaks 不一样,但 fxreq 在每种算法下都等于 FF152(因字节相同)。

## 4. www.howsmyssl.com/a/check （密码套件/组/签名算法分析，站点侧读真 FF152 截图）
| 项 | 真 FF152(浏览器实测) | fxreq | |
|---|---|---|---|
| tls_version | TLS 1.3 | TLS 1.3 | ✅ |
| given_cipher_suites | 16 个(1301,1303,1302,…,002f,0035 同序) | 同 | ✅ |
| given_named_groups | X25519MLKEM768, x25519, secp256r1/384/521, ffdhe2048/3072 | 同 | ✅ |
| given_signature_algorithms | 11 个(ecdsa_secp256r1_sha256 … rsa_pkcs1_sha1) | 同 | ✅ |
| post_quantum_key_agreement | true | true | ✅ |
| session_ticket_supported | true | true | ✅ |

## 顺带修复的真实 bug
多站测试中,scrapfly / browserleaks 会发**优雅 GOAWAY(code=0 NO_ERROR + last_stream_id)**,
而 fxreq 之前把任何 GOAWAY 当失败 → 这两站全部失败。修复:遵守 last_stream_id、GOAWAY 后继续
读完在途流(真浏览器的标准 h2 行为)。修后 4 站全部 200。这正是单站(peet)测不出、多站才暴露的问题。

## 结论
跨 4 个站点、≥8 种指纹算法变体(JA3-771 / JA3-772 / JA3N / JA4 / JA4_o / JA4_ro / JA4_r / Akamai /
peetprint / scrapfly_fp / 密码套件分析),**fxreq 与真 Firefox 152 全部一致**。
底层握手(密码套件、组含 MLKEM、签名算法、扩展、ECH、会话票据)逐项核对无差异。
