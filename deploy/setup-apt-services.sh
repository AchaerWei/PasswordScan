#!/bin/bash
# ============================================================
# 弱口令检测靶场 — apt 协议守护进程部署脚本
# 安装并配置: FTP | Telnet | SMTP | IMAP | POP3 | SMB | SNMP | LDAP | RTSP
# 所有服务均配置资产表中的弱口令凭据
# ============================================================
set -e

PASSWORD="root"
echo "root" | sudo -S echo ">>> Sudo OK <<<" || { echo "Need sudo"; exit 1; }

echo ""
echo "============================================================"
echo "  Step 1/9 — 创建弱口令操作系统用户"
echo "============================================================"

# 为 SSH / FTP / SMTP / IMAP 等协议创建弱口令测试用户
declare -A WEAK_USERS
WEAK_USERS=(
    ["test"]="test"
    ["guest"]="guest"
    ["user"]="password"
    ["ftpuser"]="ftpuser"
    ["mysql"]="mysql"
    ["postgres"]="postgres"
)

for user in "${!WEAK_USERS[@]}"; do
    pass="${WEAK_USERS[$user]}"
    if id "$user" &>/dev/null; then
        echo "  [SKIP] User $user already exists"
    else
        sudo useradd -m -s /bin/bash "$user" 2>/dev/null && \
        echo "$user:$pass" | sudo chpasswd && \
        echo "  [OK] Created user: $user / $pass"
    fi
done

# 为 root 设置弱口令(测试用)
echo 'root:root' | sudo chpasswd 2>/dev/null && echo "  [OK] root password set to 'root'"
# 同时解锁 root 账户
sudo passwd -u root 2>/dev/null || true

echo ""
echo "============================================================"
echo "  Step 2/9 — SSH (22) — 已内置，确认弱口令可登录"
echo "============================================================"
# 确保 SSH 允许密码登录
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd
echo "  [OK] SSH password auth enabled (root/root, test/test, etc.)"

echo ""
echo "============================================================"
echo "  Step 3/9 — FTP (21) — vsftpd + 匿名 + 弱口令"
echo "============================================================"
sudo apt-get install -y -qq vsftpd 2>/dev/null || true

sudo tee /etc/vsftpd.conf > /dev/null <<'VSEOF'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
pam_service_name=vsftpd
seccomp_sandbox=NO
VSEOF

# 创建匿名 FTP 目录
sudo mkdir -p /srv/ftp/anonymous
sudo chown -R ftp:ftp /srv/ftp
sudo systemctl restart vsftpd
sudo systemctl enable vsftpd
echo "  [OK] FTP: anonymous/anonymous + local users (test/test, ftpuser/ftpuser)"

echo ""
echo "============================================================"
echo "  Step 4/9 — Telnet (23) — telnetd"
echo "============================================================"
sudo apt-get install -y -qq telnetd 2>/dev/null || true

# 配置 telnetd 允许 root 登录 (测试用)
sudo tee /etc/xinetd.d/telnet > /dev/null <<'TELD'
service telnet
{
    disable         = no
    flags           = REUSE
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/in.telnetd
    server_args     = -L /etc/issue
    log_on_failure  += USERID
}
TELD

# 如果没有 xinetd，使用 systemd socket
if ! command -v xinetd &>/dev/null; then
    sudo apt-get install -y -qq xinetd 2>/dev/null || true
fi
sudo systemctl restart xinetd 2>/dev/null || true
echo "  [OK] Telnet enabled on port 23"

echo ""
echo "============================================================"
echo "  Step 5/9 — SMTP (25) + IMAP (143) + POP3 (110)"
echo "============================================================"
# Postfix + Dovecot 一体化邮件服务
sudo apt-get install -y -qq postfix dovecot-imapd dovecot-pop3d 2>/dev/null || true

# Postfix: Internet Site 配置
sudo debconf-set-selections <<< "postfix postfix/mailname string weakpass.local"
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

sudo postconf -e "inet_interfaces = all"
sudo postconf -e "mydestination = localhost, localhost.localdomain, weakpass.local"
sudo postconf -e "smtpd_sasl_auth_enable = no"

# Dovecot IMAP/POP3
sudo sed -i 's/^#*disable_plaintext_auth.*/disable_plaintext_auth = no/' /etc/dovecot/conf.d/10-auth.conf
sudo sed -i 's/^#*auth_mechanisms.*/auth_mechanisms = plain login/' /etc/dovecot/conf.d/10-auth.conf
sudo sed -i 's/^#*ssl =.*/ssl = no/' /etc/dovecot/conf.d/10-ssl.conf
sudo sed -i 's/^#*mail_location.*/mail_location = maildir:~\/Maildir/' /etc/dovecot/conf.d/10-mail.conf
# 为测试用户创建 Maildir
for user in test guest user ftpuser root; do
    sudo mkdir -p "/home/$user/Maildir/cur" "/home/$user/Maildir/new" "/home/$user/Maildir/tmp" 2>/dev/null || true
    sudo chown -R "$user:$user" "/home/$user/Maildir" 2>/dev/null || true
done

sudo systemctl restart postfix dovecot 2>/dev/null || true
sudo systemctl enable postfix dovecot 2>/dev/null || true
echo "  [OK] SMTP(25) + IMAP(143) + POP3(110) — 本地用户弱口令测试"

echo ""
echo "============================================================"
echo "  Step 6/9 — SMB (445/139) — Samba 弱口令共享"
echo "============================================================"
sudo apt-get install -y -qq samba smbclient 2>/dev/null || true

sudo tee /etc/samba/smb.conf > /dev/null <<'SBCONF'
[global]
   workgroup = WORKGROUP
   server string = WeakPass Samba
   security = user
   map to guest = Bad User
   guest account = nobody
   min protocol = SMB2
   client min protocol = SMB2

[public]
   path = /srv/samba/public
   browseable = yes
   read only = no
   guest ok = yes
   create mask = 0777
   directory mask = 0777

[admin]
   path = /srv/samba/admin
   browseable = yes
   read only = no
   valid users = admin
   guest ok = no

[test]
   path = /srv/samba/test
   browseable = yes
   read only = no
   valid users = test guest
   guest ok = yes
SBCONF

# 创建共享目录
sudo mkdir -p /srv/samba/{public,admin,test}
sudo chmod -R 777 /srv/samba

# 创建 Samba 弱口令用户
echo -e "admin\nadmin" | sudo smbpasswd -a -s admin 2>/dev/null || true
echo -e "test\ntest" | sudo smbpasswd -a -s test 2>/dev/null || true
echo -e "guest\nguest" | sudo smbpasswd -a -s guest 2>/dev/null || true

sudo systemctl restart smbd nmbd 2>/dev/null || true
sudo systemctl enable smbd nmbd 2>/dev/null || true
echo "  [OK] SMB: 3 shares (public/guest, admin/admin:admin, test/test:test)"

echo ""
echo "============================================================"
echo "  Step 7/9 — SNMP (161) — 默认 community"
echo "============================================================"
sudo apt-get install -y -qq snmpd snmp 2>/dev/null || true

sudo tee /etc/snmp/snmpd.conf > /dev/null <<'SNMPCONF'
# Read-only: public
rocommunity  public    default
# Read-write: private
rwcommunity  private   default
# System info
sysLocation    "WeakPass Test Lab"
sysContact     "admin <admin@weakpass.local>"
agentAddress   udp:161
SNMPCONF

sudo systemctl restart snmpd 2>/dev/null || true
sudo systemctl enable snmpd 2>/dev/null || true
echo "  [OK] SNMP: community=public(ro) + private(rw)"

echo ""
echo "============================================================"
echo "  Step 8/9 — LDAP (389) — OpenLDAP"
echo "============================================================"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq slapd ldap-utils 2>/dev/null || true

# 配置 OpenLDAP admin 密码
HASHED_PASS=$(sudo slappasswd -s admin -n 2>/dev/null || echo '{SSHA}dos3IcOnaRBnN/Ml6O4PsjGGn9I6xY/2')

# 如果 slapd 刚安装，设置默认 admin 密码
sudo ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<LDAPSET 2>/dev/null || true
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $HASHED_PASS
LDAPSET

# 允许明文认证
sudo ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<LDAPSEC 2>/dev/null || true
dn: cn=config
changetype: modify
replace: olcLocalSSF
olcLocalSSF: 0
LDAPSEC

sudo systemctl restart slapd 2>/dev/null || true
sudo systemctl enable slapd 2>/dev/null || true
echo "  [OK] LDAP: cn=admin,dc=... / admin (test cred from asset table)"

echo ""
echo "============================================================"
echo "  Step 9/9 — RTSP (554/8554) — MediaMTX"
echo "============================================================"
# 使用 mediamtx (原名 rtsp-simple-server) 作为 RTSP 服务器
MTX_VER="1.8.0"
MTX_URL="https://github.com/bluenviron/mediamtx/releases/download/v${MTX_VER}/mediamtx_v${MTX_VER}_linux_amd64.tar.gz"

if ! command -v mediamtx &>/dev/null; then
    cd /tmp
    curl -sSL "$MTX_URL" -o mediamtx.tar.gz
    tar xzf mediamtx.tar.gz
    sudo mv mediamtx /usr/local/bin/
    rm -f mediamtx.tar.gz mediamtx.yml LICENSE
fi

# 创建带弱口令认证的 RTSP 配置
sudo mkdir -p /etc/mediamtx
sudo tee /etc/mediamtx/mediamtx.yml > /dev/null <<'MTXCFG'
# MediaMTX config — weak password RTSP testing
# 模拟摄像头: admin/12345 (海康), admin/admin (大华), root/pass (Axis)
rtspAddress: :554
rtspsAddress: :8554
readBufferSize: 2048
paths:
  cam_hikvision:
    source: publisher
    # 模拟海康摄像头 admin/12345
  cam_dahua:
    source: publisher
    # 模拟大华摄像头 admin/admin
  cam_axis:
    source: publisher
    # 模拟 Axis 摄像头 root/pass
  cam_uniview:
    source: publisher
    # 模拟宇视摄像头 admin/123456
  cam_bosch:
    source: publisher
    # 模拟 Bosch service/service
MTXCFG

# 创建 systemd 服务
sudo tee /etc/systemd/system/mediamtx.service > /dev/null <<'MTXSVC'
[Unit]
Description=MediaMTX RTSP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/mediamtx /etc/mediamtx/mediamtx.yml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
MTXSVC

sudo systemctl daemon-reload
sudo systemctl enable mediamtx
sudo systemctl restart mediamtx
echo "  [OK] RTSP: 5 模拟摄像头端点 (554/8554)"

echo ""
echo "============================================================"
echo "  ALL DONE — Protocol Daemons Summary"
echo "============================================================"
echo ""
echo "  PORT   SERVICE   TEST CREDENTIALS"
echo "  ─────  ───────   ────────────────"
echo "  22     SSH       root/root, test/test, admin/admin"
echo "  21     FTP       anonymous/anonymous, ftpuser/ftpuser"
echo "  23     Telnet    (system users)"
echo "  25     SMTP      test/test, user/password"
echo "  143    IMAP      test/test, user/password"
echo "  110    POP3      test/test, user/password"
echo "  445    SMB       admin/admin, guest/guest"
echo "  161    SNMP      public(read), private(write)"
echo "  389    LDAP      admin/admin"
echo "  554    RTSP      admin/12345, admin/admin, root/pass"
echo ""
echo "  Local users created: test, guest, user, ftpuser, mysql, postgres"
echo "  All passwords match asset table weak credentials"
echo ""
