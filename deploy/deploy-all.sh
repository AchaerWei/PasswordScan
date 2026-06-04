#!/bin/bash
# ============================================================
# 弱口令检测靶场 — 一键部署脚本 (Master)
# 在远程服务器上执行此脚本完成全部部署
# ============================================================
set -e
PASS="root"
LAB_DIR="/home/ubuntu/weakpass-lab"
cd "$LAB_DIR"

echo "root" | sudo -S echo ">>> Sudo OK <<<"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   弱口令检测靶场 — 远程一键部署                      ║"
echo "║   服务器: $(hostname -I | awk '{print $1}')                       ║"
echo "║   日期:   $(date +%Y-%m-%d)                         ║"
echo "╚══════════════════════════════════════════════════════╝"

# ============================================================
# Phase 1: Docker 容器
# ============================================================
echo ""
echo "============================================"
echo " Phase 1/3 — Docker Compose 启动容器"
echo "============================================"

# Create Tomcat config directory
mkdir -p ./tomcat-conf
cp -f tomcat-users.xml ./tomcat-conf/

# Create Jenkins init directory
mkdir -p ./jenkins-init
cp -f jenkins-init.groovy ./jenkins-init/

echo "$PASS" | sudo -S docker compose down --remove-orphans 2>/dev/null || true
echo "$PASS" | sudo -S docker compose pull 2>/dev/null
echo "$PASS" | sudo -S docker compose up -d 2>&1

echo ""
echo ">>> Waiting for services to initialize (60 seconds)..."
sleep 60

# ============================================================
# Phase 2: Apt 协议守护进程
# ============================================================
echo ""
echo "============================================"
echo " Phase 2/3 — 协议守护进程 (FTP/Telnet/SMTP/...) "
echo "============================================"
bash setup-apt-services.sh

# ============================================================
# Phase 3: 验证
# ============================================================
echo ""
echo "============================================"
echo " Phase 3/3 — 部署验证"
echo "============================================"

echo ""
echo "--- Docker 容器状态 ---"
echo "$PASS" | sudo -S docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null

echo ""
echo "--- 开放端口 ---"
echo "$PASS" | sudo -S ss -tlnp 2>/dev/null | grep -v "127.0.0"

echo ""
echo "--- 弱口令测试用户 ---"
echo "$PASS" | sudo -S cat /etc/shadow 2>/dev/null | grep -E '^(test|guest|user|ftpuser|mysql|postgres):' | cut -d: -f1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  DEPLOYMENT COMPLETE                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                            ║"
echo "║  靶场地址: $(hostname -I | awk '{print $1}')                                          ║"
echo "║                                                            ║"
echo "║  Docker 服务 (docker ps 查看):                              ║"
echo "║  ─────────                                                  ║"
echo "║  MySQL 8.0      :3306   root/root                          ║"
echo "║  PostgreSQL 16  :5432   postgres/postgres                  ║"
echo "║  Redis (auth)   :6379   (pass:redis)                       ║"
echo "║  Redis (unauth) :6380   (无密码)                           ║"
echo "║  MongoDB 7      :27017  admin/admin                        ║"
echo "║  Elasticsearch  :9200   elastic/changeme                   ║"
echo "║  InfluxDB       :8086   admin/admin                        ║"
echo "║  ClickHouse     :8123   default/(空)                       ║"
echo "║  CouchDB        :5984   admin/admin                        ║"
echo "║  Neo4j          :7474   neo4j/neo4j                        ║"
echo "║  RabbitMQ       :15672  guest/guest                        ║"
echo "║  ActiveMQ       :8161   admin/admin                        ║"
echo "║  Tomcat         :8081   tomcat/tomcat, admin/admin         ║"
echo "║  WildFly        :9990   admin/admin                        ║"
echo "║  Jenkins        :8080   admin/admin                        ║"
echo "║  SonarQube      :9000   admin/admin                        ║"
echo "║  Nexus          :8084   admin/admin123                     ║"
echo "║  Gitea          :3001   (首次配置)                         ║"
echo "║  Grafana        :3000   admin/admin                        ║"
echo "║  Kibana         :5601   elastic/changeme                   ║"
echo "║  Portainer      :9443   admin/admin123                     ║"
echo "║  Zookeeper      :2181   (无认证)                           ║"
echo "║                                                            ║"
echo "║  系统服务:                                                  ║"
echo "║  ─────────                                                  ║"
echo "║  SSH      :22     root/root, test/test                     ║"
echo "║  FTP      :21     anonymous/anonymous, ftpuser/ftpuser     ║"
echo "║  Telnet   :23     (system users)                           ║"
echo "║  SMTP     :25     test/test, user/password                 ║"
echo "║  IMAP     :143    test/test                                ║"
echo "║  POP3     :110    test/test                                ║"
echo "║  SMB      :445    admin/admin, guest/guest                 ║"
echo "║  SNMP     :161    public / private                         ║"
echo "║  LDAP     :389    admin/admin                              ║"
echo "║  RTSP     :554    admin/12345, admin/admin                 ║"
echo "║  RDP      :3389   (xrdp — 现有)                            ║"
echo "║  VNC      :5900   (现有 GNOME Remote Desktop)               ║"
echo "║                                                            ║"
echo "║  内存使用: docker stats 查看                                ║"
echo "║  管理面板: https://$(hostname -I | awk '{print $1}'):9443       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
