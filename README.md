<p align="center">
  <img src="https://www.offsec.com/_astro/1a84f0c68944e562affe39ab28f4997480c24cef-1200x628_Z1o7Q7w.webp" alt="OffSec OSCP" width="800">
</p>

# OSCP / OffSec ペンテスト ナレッジ

OSCP / PEN-200 の学習・試験対策で実際に使ったコマンド、ワンライナー、攻撃フローを整理したリポジトリ。

---

## 📚 構成

| ファイル | 内容 |
|----------|------|
| [`cheatsheet.md`](./cheatsheet.md) | OSCP 全フェーズ網羅チートシート（Recon → Web → 初期侵入 → PrivEsc → AD → ハッシュ → ピボット） |
| [`writeups/`](./writeups/) | マシン別 writeup（Recon → Foothold → PrivEsc → Lateral → DA） |
| [`templates/`](./templates/) | 試験 / レポート用テンプレート |

---

## 🗂️ チートシート目次

| § | テーマ |
|---|--------|
| 0 | 変数規約（`$ip` / `$lhost` / `$lport` / `$dc` / `$domain` / `<USER>` / `<PASS>` / `<NTHASH>`） |
| 1 | 環境準備（ポート規約・/etc/hosts・VPN） |
| 2 | 情報収集（rustscan / nmap） |
| 3 | サービス別列挙（Web / SMB / LDAP / Kerberos / MSSQL / MySQL / PostgreSQL / SMTP / DNS / SNMP / RDP / WinRM / BloodHound） |
| 4 | Web 脆弱性（SQLi / LFI / CmdInj / Upload / Deser / SSRF） |
| 5 | 初期侵入（リスナー / msfvenom / リバースシェルワンライナー / シェル安定化） |
| 6 | Linux PrivEsc（linpeas / SUID / sudo / cron / capabilities / 認証情報ハント） |
| 7 | Windows PrivEsc（winPEAS / Defender 回避 / Potato 系 / RDP 有効化 / AD on-host 列挙） |
| 8 | AD 攻撃（Kerberoast / AS-REP / PtH / DCSync / ACL / ADCS / NTLM Relay / mimikatz） |
| 9 | ハッシュクラック（john / hashcat + `-m` 早見表） |
| 10 | ピボッティング（chisel / ligolo-ng / SSH ポートフォワード） |
| 11 | ユーティリティ（ファイルサーバ / コンパイル / Base64 等） |

---

## 🛠️ よく使うコマンド早見

```bash
# ターゲット変数のセットアップ
export ip=10.10.10.5
export lhost=$(ip -4 addr show tun0 | awk '/inet/{print $2}' | cut -d/ -f1)
export lport=4444

# 高速 Recon
rustscan -a $ip --ulimit 5000 -- -A -sV

# Web ディレクトリ列挙
feroxbuster -u http://$ip -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -t 50 -s 200,301,302,401,403 -x php,html,txt

# SMB 列挙（認証なし）
nxc smb $ip -u 'guest' -p '' --shares --rid-brute

# リバースシェル待ち受け
rlwrap -cAr nc -lvnp $lport
```

詳細は [`cheatsheet.md`](./cheatsheet.md) を参照。

---

## 📖 参考リソース

- [PEN-200 公式](https://www.offsec.com/courses/pen-200/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/) / [LOLBAS](https://lolbas-project.github.io/)
- [Hashcat hash modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Specter Ops Cypher Library](https://queries.specterops.io/)

---

## ⚖️ 免責

本リポジトリの内容は教育目的に限る。許可のない第三者システムへの使用は不正アクセス禁止法に抵触する可能性がある。利用者の責任で運用すること。
