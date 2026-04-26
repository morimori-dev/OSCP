---
fileClass: writeup
ステータス:
OS:
攻撃対象:
初期侵入サービス:
初期侵入コンポーネント:
初期侵入手法:
初期侵入tools:
初期侵入CVE:
権限昇格:
権限昇格サービス:
権限昇格tools:
権限昇格CVE:
攻撃パターン:
資格情報ソース:
重要ファイル:
---
# Room Link




# 認証情報
---

```text
```




# 1. PortScan
---
## Rustscan
```bash

```

## Nmap
```bash

```

## Port Enumeration チェックリスト

| Symbol | Meaning       |
| ------ | ------------- |
| ☐      | 未確認           |
| ✅      | アクセス可 / 認証成功  |
| ❌      | アクセス不可 / 認証失敗 |
| —      | 該当なし          |
| 🔑     | 有効なcreds取得済み  |
| ⚠️     | 要追加調査         |

| Port  | Service       | Protocol | Anonymous/Null          | Auth Creds | Notes                       |
| ----- | ------------- | -------- | ----------------------- | ---------- | --------------------------- |
| 21    | FTP           | TCP      | ☐ anonymous login       | ☐          |                             |
| 22    | SSH           | TCP      | —                       | ☐          |                             |
| 25    | SMTP          | TCP      | ☐ VRFY/EXPN             | ☐          |                             |
| 53    | DNS           | TCP/UDP  | ☐ zone transfer         | —          | `dig axfr domain @ip`       |
| 80    | HTTP          | TCP      | ☐                       | ☐          | IIS / Apache / Nginx        |
| 88    | Kerberos      | TCP      | ☐ kerbrute enum         | ☐ AS-REP   |                             |
| 110   | POP3          | TCP      | —                       | ☐          |                             |
| 111   | RPCbind       | TCP      | ☐ rpcinfo               | —          | NFS確認                       |
| 135   | MSRPC         | TCP      | ☐ rpcclient             | ☐          |                             |
| 139   | NetBIOS       | TCP      | ☐                       | ☐          |                             |
| 143   | IMAP          | TCP      | —                       | ☐          |                             |
| 389   | LDAP          | TCP      | ☐ anonymous bind        | ☐          | `ldapsearch -x`             |
| 443   | HTTPS         | TCP      | ☐                       | ☐          | 証明書のCN/SAN確認                |
| 445   | SMB           | TCP      | ☐ null session / shares | ☐          | `netexec smb --shares`      |
| 464   | kpasswd       | TCP      | —                       | —          | Kerberos password change    |
| 593   | RPC over HTTP | TCP      | —                       | —          |                             |
| 636   | LDAPS         | TCP      | ☐ anonymous bind        | ☐          |                             |
| 1433  | MSSQL         | TCP      | ☐ sa空パス                 | ☐          | `netexec mssql` / sysadmin? |
| 1521  | Oracle        | TCP      | —                       | ☐          | odat                        |
| 2049  | NFS           | TCP      | ☐ showmount             | —          | `showmount -e`              |
| 3268  | GC LDAP       | TCP      | ☐                       | ☐          | Global Catalog              |
| 3269  | GC LDAPS      | TCP      | ☐                       | ☐          |                             |
| 3306  | MySQL         | TCP      | ☐ root空パス               | ☐          |                             |
| 3389  | RDP           | TCP      | —                       | ☐          | NLA有無確認                     |
| 4369  | EPMD          | TCP      | ☐                       | —          | Erlang                      |
| 5432  | PostgreSQL    | TCP      | ☐ postgres空パス           | ☐          |                             |
| 5900  | VNC           | TCP      | ☐ no-auth               | ☐          |                             |
| 5985  | WinRM HTTP    | TCP      | —                       | ☐          | `evil-winrm`                |
| 5986  | WinRM HTTPS   | TCP      | —                       | ☐          |                             |
| 6379  | Redis         | TCP      | ☐ no-auth               | ☐          |                             |
| 8080  | HTTP Alt      | TCP      | ☐                       | ☐          | Tomcat / Werkzeug / etc     |
| 8443  | HTTPS Alt     | TCP      | ☐                       | ☐          |                             |
| 8530  | WSUS HTTP     | TCP      | ☐                       | ☐          |                             |
| 8531  | WSUS HTTPS    | TCP      | ☐                       | ☐          |                             |
| 9389  | ADWS          | TCP      | —                       | ☐          | .NET Message Framing        |
| 11211 | Memcached     | TCP      | ☐ no-auth               | —          |                             |
| 27017 | MongoDB       | TCP      | ☐ no-auth               | ☐          |                             |

# 2. Local Shell
---












# 3.Privilege Escalation
---








# 4.全体図
---

```mermaid
以下のwriteupをもとに、攻撃フローをmermaid形式でまとめてください。

## 条件
- flowchart LR（横並び）
- スキャン / 初期侵入 / 権限昇格 の3つのsubgraph
- 各subgraphはdirection TB（縦並び）
- ノードは簡潔に：ツール名・発見内容・実行コマンドを改行で記載
- subgraph間は SCAN --> INITIAL --> PRIVESC で接続
- 絵文字はそれぞれ 🔍💥⬆️

## writeup
[ここにwriteupを貼る]
```